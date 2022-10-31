mod proto;

extern crate lazy_static;
use async_rdma::{
    self, ConnectionType, Gid, LocalMr, LocalMrReadAccess, LocalMrWriteAccess, MRManageStrategy,
    MrAccess, MrTokenBuilder, QueuePairEndpointBuilder, Rdma, RdmaBuilder, RemoteMr, MTU,
};
use clippy_utilities::Cast;
use futures::channel::oneshot;
use futures::executor::block_on;
use futures::{FutureExt, TryFutureExt};
use grpcio::{ChannelBuilder, Environment, ResourceQuota, ServerBuilder};
use lazy_static::lazy_static;
use log::debug;
use proto::message::{
    CheckQpStatusResponse, ConnectQpResponse, CreateMrResponse, LocalCheckMemResponse,
    LocalRecvResponse, LocalWriteResponse, NotifyCqResponse, OpenDeviceResponce,
    PollCompleteResponse, QueryGidResponse, QueryPortResponse, RecvPktResponse,
    RemoteAtomicCasResponse, RemoteReadResponse, RemoteSendResponse, RemoteWriteImmResponse,
    RemoteWriteResponse, UnblockRetryResponse, VersionResponse,
};
use proto::side_grpc::{self, Side};
use rdma_sys::ibv_mtu;
use std::alloc::Layout;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Write;
use std::ops::{Add, Div};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::{env, io};
use tokio::{runtime, sync::RwLock};

/// If imm flag was initialized.
static mut INIT_IMM_FLAG: parking_lot::Mutex<bool> = parking_lot::Mutex::new(false);

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let env = Arc::new(Environment::new(1));
    let quota = ResourceQuota::new(None).resize_memory(1024 * 1024);
    let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota);
    let side = SideImpl {};
    let service = side_grpc::create_side(side);

    let args: Vec<String> = env::args().collect();
    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind("0.0.0.0", args[1].parse().unwrap())
        .channel_args(ch_builder.build_args())
        .build()
        .unwrap();

    server.start();

    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(60));
        tx.send(())
    });
    let _ = block_on(rx);
    let _ = block_on(server.shutdown());

    Ok(())
}

lazy_static! {
    static ref RDMA_MAP: Arc<RwLock<HashMap<String, Rdma>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref MR_MAP: Arc<RwLock<HashMap<usize, LocalMr>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref RUNTIME: runtime::Runtime = runtime::Runtime::new().unwrap();
    static ref RDMA_MR_MAP: Arc<RwLock<HashMap<String, Vec<usize>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

fn try_mtu_from_u32(value: u32) -> Result<MTU, io::Error> {
    match value {
        ibv_mtu::IBV_MTU_256 => Ok(MTU::MTU256),
        ibv_mtu::IBV_MTU_512 => Ok(MTU::MTU512),
        ibv_mtu::IBV_MTU_1024 => Ok(MTU::MTU1024),
        ibv_mtu::IBV_MTU_2048 => Ok(MTU::MTU2048),
        ibv_mtu::IBV_MTU_4096 => Ok(MTU::MTU4096),
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("wrong mtu value{:?}", value),
        )),
    }
}

#[derive(Clone)]
struct SideImpl {}

impl Side for SideImpl {
    fn version(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::VersionRequest,
        sink: grpcio::UnarySink<proto::message::VersionResponse>,
    ) {
        let mut resp = VersionResponse::default();
        resp.set_version("0.1".to_string());
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn open_device(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::OpenDeviceRequest,
        sink: grpcio::UnarySink<proto::message::OpenDeviceResponce>,
    ) {
        let dev_name = req.get_dev_name().to_string();
        let mtu = try_mtu_from_u32((req.get_mtu().div(256) as f32).add(1.0).log2() as u32).unwrap();

        let resp = RUNTIME.block_on(async move {
            let rdma = RdmaBuilder::default()
                .set_raw(true)
                .set_mr_strategy(MRManageStrategy::Raw)
                .set_conn_type(ConnectionType::RCIBV)
                .set_port_num(req.get_ib_port_num().cast())
                .set_qp_access(req.get_access_flag().cast())
                .set_gid_index(req.get_gid_idx().cast())
                .set_timeout(req.get_timeout().cast())
                .set_retry_cnt(req.get_retry().cast())
                .set_rnr_retry(req.get_rnr_retry().cast())
                .set_mtu(mtu)
                .set_sq_psn(req.get_sq_start_psn())
                .set_rq_psn(req.get_rq_start_psn())
                .set_max_rd_atomic(req.get_max_rd_atomic().cast())
                .set_max_dest_rd_atomic(req.get_max_dest_rd_atomic().cast())
                .set_min_rnr_timer(req.get_min_rnr_timer().cast());

            let mut guard = unsafe { INIT_IMM_FLAG.lock() };
            let rdma = if *guard {
                rdma
            } else {
                *guard = true;
                rdma.set_imm_flag_in_wc(req.get_imm_flag()).unwrap()
            };

            let rdma = if req.get_dev_name().is_empty() {
                rdma
            } else {
                rdma.set_dev(req.get_dev_name())
            }
            .build()
            .unwrap();

            let ep = rdma.get_qp_endpoint();

            let mut resp = OpenDeviceResponce::default();
            resp.set_dev_name(dev_name.to_string());
            resp.set_qp_num(*ep.qp_num());
            resp.set_lid((*ep.lid()).cast());
            resp.set_gid_raw((*ep.gid()).as_raw().to_vec());

            let old_rdma = RDMA_MAP.write().await.insert(dev_name.clone(), rdma);
            // clean up old lmrs
            if old_rdma.is_some() {
                let lmrs = RDMA_MR_MAP.write().await.remove(&dev_name).unwrap();
                let mut lmr_map = MR_MAP.write().await;
                for mr in lmrs {
                    let mr = lmr_map.remove(&mr);
                    debug!("drop mr :{:?}", mr);
                }
            }

            resp
        });

        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    #[tokio::main]
    async fn create_mr(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::CreateMrRequest,
        sink: grpcio::UnarySink<proto::message::CreateMrResponse>,
    ) {
        let dev_name = req.get_dev_name();
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(dev_name).unwrap();

        let mr = rdma
            .alloc_local_mr_with_access(
                Layout::from_size_align(req.get_len().cast(), 1).unwrap(),
                req.get_flag().cast(),
            )
            .unwrap();

        let mut resp = CreateMrResponse::default();
        resp.set_addr(mr.addr().cast());
        resp.set_len(mr.length().cast());
        resp.set_rkey(mr.rkey());
        resp.set_lkey(mr.lkey());

        let mut local_mr_map = MR_MAP.write().await;
        let mr_id = local_mr_map.len();
        local_mr_map.insert(mr_id, mr);

        // insert mr_id and related rdma into the map
        match RDMA_MR_MAP.write().await.entry(dev_name.to_string()) {
            Entry::Occupied(mut occ) => {
                let mr_ids = occ.get_mut();
                mr_ids.push(mr_id);
            }
            Entry::Vacant(vac) => {
                let _ = vac.insert(vec![mr_id]);
            }
        };

        resp.set_mr_id(mr_id.cast());

        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    #[tokio::main]
    async fn connect_qp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::ConnectQpRequest,
        sink: grpcio::UnarySink<proto::message::ConnectQpResponse>,
    ) {
        let mut rdma_map = RDMA_MAP.write().await;
        let rdma = rdma_map.get_mut(req.get_dev_name()).unwrap();

        let remote = QueuePairEndpointBuilder::default()
            .qp_num(req.get_remote_qp_num())
            .lid(req.get_remote_lid().cast())
            .gid(Gid::from_raw(req.get_remote_gid().try_into().unwrap()))
            .build()
            .unwrap();

        rdma.ibv_connect(remote).await.unwrap();

        let resp = ConnectQpResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    #[tokio::main]
    async fn remote_read(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteReadRequest,
        sink: grpcio::UnarySink<proto::message::RemoteReadResponse>,
    ) {
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(req.get_dev_name()).unwrap();

        let mut lmr_map = MR_MAP.write().await;
        let mr_id: usize = req.get_mr_id().cast();
        let mut lmr = lmr_map
            .get_mut(&mr_id)
            .unwrap()
            .get_mut(0..req.get_len().cast())
            .unwrap();

        let token = MrTokenBuilder::default()
            .addr(req.get_remote_addr().try_into().unwrap())
            .len(req.get_len().try_into().unwrap())
            .rkey(req.get_remote_key())
            .build()
            .unwrap();
        let rmr = RemoteMr::new(token);

        rdma.read(&mut lmr, &rmr)
            .await
            .unwrap_or_else(|e| error_check(req.get_allow_err(), e));

        let resp = RemoteReadResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    #[tokio::main]
    async fn remote_write(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteWriteRequest,
        sink: grpcio::UnarySink<proto::message::RemoteWriteResponse>,
    ) {
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(req.get_dev_name()).unwrap();

        let mr_id: usize = req.get_mr_id().cast();
        let lmr_map = MR_MAP.write().await;
        let lmr = lmr_map
            .get(&mr_id)
            .unwrap()
            .get(0..req.get_len().cast())
            .unwrap();

        let token = MrTokenBuilder::default()
            .addr(req.get_remote_addr().try_into().unwrap())
            .len(req.get_len().try_into().unwrap())
            .rkey(req.get_remote_key())
            .build()
            .unwrap();
        let mut rmr = RemoteMr::new(token);

        rdma.write(&lmr, &mut rmr)
            .await
            .unwrap_or_else(|e| error_check(req.get_allow_err(), e));

        let resp = RemoteWriteResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    #[tokio::main]
    async fn remote_atomic_cas(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteAtomicCasRequest,
        sink: grpcio::UnarySink<proto::message::RemoteAtomicCasResponse>,
    ) {
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(req.get_dev_name()).unwrap();

        let token = MrTokenBuilder::default()
            .addr(req.get_remote_addr().try_into().unwrap())
            .len(8)
            .rkey(req.get_remote_key())
            .build()
            .unwrap();

        let mut rmr = RemoteMr::new(token);

        rdma.atomic_cas(req.old_value, req.new_value, &mut rmr)
            .await
            .unwrap_or_else(|e| error_check(req.get_allow_err(), e));

        let resp = RemoteAtomicCasResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    #[tokio::main]
    async fn local_recv(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::LocalRecvRequest,
        sink: grpcio::UnarySink<proto::message::LocalRecvResponse>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let _task = RUNTIME.spawn(async move {
            let rdma_map = RDMA_MAP.read().await;
            let rdma = rdma_map.get(req.get_dev_name()).unwrap();

            let (recv_lmr, imm) = rdma
                .receive_raw_with_imm_fn(
                    Layout::from_size_align(req.get_len().cast(), 1).unwrap(),
                    || tx.send(()).unwrap(),
                )
                .await
                .unwrap();

            let mr_id: usize = req.get_mr_id().cast();
            let mut lmr_map = MR_MAP.write().await;
            let lmr = lmr_map.get_mut(&mr_id).unwrap();

            // TODO: add uer defined lmr api for async-rdma
            let _len = lmr.as_mut_slice().write(*recv_lmr.as_slice()).unwrap();

            // check imm data
            if req.get_imm() != 0 {
                assert_eq!(imm.unwrap(), req.get_imm())
            }
        });
        rx.await.unwrap();
        let resp = LocalRecvResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn poll_complete(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::PollCompleteRequest,
        sink: grpcio::UnarySink<proto::message::PollCompleteResponse>,
    ) {
        // TODO: Polling will be completed automatically, add related APIs for async-rdma if need
        let same = true;
        let mut resp = PollCompleteResponse::default();
        resp.set_same(same);
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    #[tokio::main]
    async fn remote_send(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteSendRequest,
        sink: grpcio::UnarySink<proto::message::RemoteSendResponse>,
    ) {
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(req.get_dev_name()).unwrap();

        let mut lmr_map = MR_MAP.write().await;
        let mr_id: usize = req.get_mr_id().cast();
        let lmr = lmr_map
            .get_mut(&mr_id)
            .unwrap()
            .get_mut(0..req.get_len().cast())
            .unwrap();

        rdma.send_raw(&lmr)
            .await
            .unwrap_or_else(|e| error_check(req.get_allow_err(), e));

        let resp = RemoteSendResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    // recv_pkt is too low level for rust side, which is processed by the driver and hardware
    fn recv_pkt(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::RecvPktRequest,
        sink: grpcio::UnarySink<proto::message::RecvPktResponse>,
    ) {
        let resp = RecvPktResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    // can do nothing on retrying
    fn unblock_retry(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::UnblockRetryRequest,
        sink: grpcio::UnarySink<proto::message::UnblockRetryResponse>,
    ) {
        let resp = UnblockRetryResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    #[tokio::main]
    async fn query_port(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::QueryPortRequest,
        sink: grpcio::UnarySink<proto::message::QueryPortResponse>,
    ) {
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(req.get_dev_name()).unwrap();

        let lid = *rdma.get_qp_endpoint().lid();

        let mut resp = QueryPortResponse::default();
        resp.set_lid(lid.cast());
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    #[tokio::main]
    async fn query_gid(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::QueryGidRequest,
        sink: grpcio::UnarySink<proto::message::QueryGidResponse>,
    ) {
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(req.get_dev_name()).unwrap();

        let ep = rdma.get_qp_endpoint();

        let mut resp = QueryGidResponse::default();
        resp.set_gid_raw(ep.gid().as_raw().to_vec());
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    #[tokio::main]
    async fn local_write(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::LocalWriteRequest,
        sink: grpcio::UnarySink<proto::message::LocalWriteResponse>,
    ) {
        let mut lmr_map = MR_MAP.write().await;
        let mr_id: usize = req.get_mr_id().cast();
        let lmr = lmr_map.get_mut(&mr_id).unwrap();

        let offset: usize = req.get_offset().cast();
        let len: usize = req.get_len().cast();

        let _len = lmr
            .get_mut(offset..offset.saturating_add(len))
            .unwrap()
            .as_mut_slice()
            .write(req.get_content())
            .unwrap();

        let resp = LocalWriteResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    #[tokio::main]
    async fn check_qp_status(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::CheckQpStatusRequest,
        sink: grpcio::UnarySink<proto::message::CheckQpStatusResponse>,
    ) {
        let state = RDMA_MAP
            .read()
            .await
            .get(req.get_dev_name())
            .unwrap()
            .query_qp_state()
            .unwrap();

        let is_eq = state == req.get_status().into();

        let mut resp = CheckQpStatusResponse::default();
        resp.set_same(is_eq);
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    #[tokio::main]
    async fn local_check_mem(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::LocalCheckMemRequest,
        sink: grpcio::UnarySink<proto::message::LocalCheckMemResponse>,
    ) {
        let lmr_map = MR_MAP.read().await;
        let mr_id: usize = req.get_mr_id().cast();
        let lmr = lmr_map.get(&mr_id).unwrap();

        let offset = req.get_offset();
        let expected = req.get_expected();

        let is_eq = offset
            .iter()
            .zip(expected)
            .map(|(off, content)| -> bool {
                let off_usize: usize = (*off).cast();
                let slice = lmr
                    .get(off_usize..(off_usize.saturating_add(content.len())))
                    .unwrap();
                let value = *slice.as_slice();
                debug!("local check real data {:?} for offset {}", value, off_usize);
                content
                    .iter()
                    .zip(value)
                    .map(|(x, y)| x.cmp(y))
                    .find(|&ord| ord != std::cmp::Ordering::Equal)
                    .unwrap_or(content.len().cmp(&value.len()))
                    == std::cmp::Ordering::Equal
            })
            .filter(|cmp| -> bool { !cmp })
            .count()
            == 0;

        let mut resp = LocalCheckMemResponse::new();
        resp.set_same(is_eq);

        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    #[tokio::main]
    async fn remote_write_imm(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteWriteImmRequest,
        sink: grpcio::UnarySink<proto::message::RemoteWriteImmResponse>,
    ) {
        let rdma_map = RDMA_MAP.read().await;
        let rdma = rdma_map.get(req.get_dev_name()).unwrap();

        let mut lmr_map = MR_MAP.write().await;
        let mr_id: usize = req.get_mr_id().cast();
        let lmr = lmr_map
            .get_mut(&mr_id)
            .unwrap()
            .get_mut(0..req.get_len().cast())
            .unwrap();

        let token = MrTokenBuilder::default()
            .addr(req.get_remote_addr().try_into().unwrap())
            .len(req.get_len().try_into().unwrap())
            .rkey(req.get_remote_key())
            .build()
            .unwrap();

        let mut rmr = RemoteMr::new(token);
        rdma.write_with_imm(&lmr, &mut rmr, req.get_imm_data())
            .await
            .unwrap_or_else(|e| error_check(req.get_allow_err(), e));

        let resp = RemoteWriteImmResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn notify_cq(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::NotifyCqRequest,
        sink: grpcio::UnarySink<proto::message::NotifyCqResponse>,
    ) {
        let resp = NotifyCqResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn create_pd(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::CreatePdRequest,
        sink: grpcio::UnarySink<proto::message::CreatePdResponse>,
    ) {
        // too low level for rust side, not impl yet
        grpcio::unimplemented_call!(ctx, sink)
    }

    fn create_cq(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::CreateCqRequest,
        sink: grpcio::UnarySink<proto::message::CreateCqResponse>,
    ) {
        // too low level for rust side, not impl yet
        grpcio::unimplemented_call!(ctx, sink)
    }

    fn create_qp(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::CreateQpRequest,
        sink: grpcio::UnarySink<proto::message::CreateQpResponse>,
    ) {
        // too low level for rust side, not impl yet
        grpcio::unimplemented_call!(ctx, sink)
    }

    fn modify_qp(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::ModifyQpRequest,
        sink: grpcio::UnarySink<proto::message::ModifyQpResponse>,
    ) {
        // too low level for rust side, not impl yet
        grpcio::unimplemented_call!(ctx, sink)
    }

    fn set_hook(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: proto::message::SetHookRequest,
        sink: grpcio::UnarySink<proto::message::SetHookResponse>,
    ) {
        // too low level for rust side, not impl yet
        grpcio::unimplemented_call!(ctx, sink)
    }
}

fn error_check(allow_err: bool, error: io::Error) {
    if allow_err {
        debug!("allowed error: {:?}", error)
    } else {
        panic!("{:?}", error);
    }
}
