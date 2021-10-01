mod proto;

extern crate lazy_static;
use async_rdma::basic as rdma;
use futures::channel::oneshot;
use futures::executor::block_on;
use futures::{FutureExt, TryFutureExt};
use grpcio::{ChannelBuilder, Environment, ResourceQuota, ServerBuilder};
use lazy_static::lazy_static;
use proto::message::{
    ConnectQpResponse, CreateCqResponse, CreateMrResponse, CreatePdResponse, CreateQpResponse,
    LocalCheckMemResponse, LocalRecvResponse, LocalWriteResponse, OpenDeviceResponce,
    PollCompleteResponse, QueryGidResponse, QueryPortResponse, RecvPktResponse,
    RemoteAtomicCasResponse, RemoteReadResponse, RemoteSendResponse, RemoteWriteResponse,
    UnblockRetryResponse, VersionResponse,
};
use proto::side_grpc::{self, Side};
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
//use std::io::{self, Read};
use log::debug;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use utilities::Cast;

fn main() -> anyhow::Result<()> {
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
    static ref DEV_MAP: RwLock<HashMap<String, rdma::ibv::IbvCtx>> = RwLock::new(HashMap::new());
    static ref QP_MAP: RwLock<Vec<rdma::ibv::IbvQp>> = RwLock::new(vec![]);
    static ref PD_MAP: RwLock<Vec<rdma::ibv::IbvPd>> = RwLock::new(vec![]);
    static ref CQ_MAP: RwLock<Vec<(rdma::ibv::IbvCq, rdma::ibv::IbvEventChannel)>> =
        RwLock::new(vec![]);
    static ref MR_MAP: RwLock<Vec<Pin<Vec<u8>>>> = RwLock::new(vec![]);
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
        debug!("Get open_device request");
        let (ibv_context, dev_name) = rdma::ibv::open_ib_ctx(&req.dev_name);
        DEV_MAP
            .write()
            .unwrap()
            .insert(dev_name.clone(), ibv_context);

        let mut resp = OpenDeviceResponce::default();
        resp.set_dev_name(dev_name);
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn create_pd(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::CreatePdRequest,
        sink: grpcio::UnarySink<proto::message::CreatePdResponse>,
    ) {
        let local_dev_map = DEV_MAP.read().unwrap();
        let ibv_ctx = local_dev_map.get(req.get_dev_name()).unwrap();
        let pd = rdma::ibv::create_pd(*ibv_ctx);
        let mut local_pd_map = PD_MAP.write().unwrap();
        local_pd_map.push(pd);

        let mut resp = CreatePdResponse::default();
        resp.set_pd_id((local_pd_map.len() - 1).cast());
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn create_mr(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::CreateMrRequest,
        sink: grpcio::UnarySink<proto::message::CreateMrResponse>,
    ) {
        let local_pd_map = PD_MAP.read().unwrap();
        let ibv_pd = local_pd_map.get(req.get_pd_id().cast::<usize>()).unwrap();
        let mr = rdma::ibv::create_mr(
            req.get_len().cast(),
            *ibv_pd,
            rdma_sys::ibv_access_flags(req.get_flag().cast()),
        );

        let mut resp = CreateMrResponse::default();
        resp.set_addr(rdma::util::ptr_to_usize(mr.1.as_ptr()).cast());
        resp.set_len(mr.1.len().cast());
        resp.set_rkey(unsafe { *mr.0.inner }.rkey);
        resp.set_lkey(unsafe { *mr.0.inner }.lkey);

        let mut local_mr_map = MR_MAP.write().unwrap();
        local_mr_map.push(mr.1);
        resp.set_mr_id((local_mr_map.len() - 1).cast());

        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn create_cq(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::CreateCqRequest,
        sink: grpcio::UnarySink<proto::message::CreateCqResponse>,
    ) {
        let local_dev_map = DEV_MAP.read().unwrap();
        let ibv_ctx = local_dev_map.get(&req.dev_name).unwrap();
        let cq = rdma::ibv::create_cq(*ibv_ctx, req.cq_size);
        let mut local_cq_map = CQ_MAP.write().unwrap();
        local_cq_map.push(cq);

        let mut resp = CreateCqResponse::default();
        resp.set_cq_id((local_cq_map.len() - 1).cast());

        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn create_qp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::CreateQpRequest,
        sink: grpcio::UnarySink<proto::message::CreateQpResponse>,
    ) {
        debug!("cq_id {}, pd_id {}", req.get_cq_id(), req.get_pd_id());
        let qp = rdma::ibv::create_qp(
            CQ_MAP
                .read()
                .unwrap()
                .get(req.get_cq_id().cast::<usize>())
                .unwrap()
                .0,
            *PD_MAP
                .read()
                .unwrap()
                .get(req.get_pd_id().cast::<usize>())
                .unwrap(),
        );

        let qp_num = unsafe { (*qp.inner).qp_num };
        let mut local_qp_map = QP_MAP.write().unwrap();
        local_qp_map.push(qp.clone());

        let mut resp = CreateQpResponse::default();
        resp.set_qp_id((local_qp_map.len() - 1).cast());
        resp.set_qp_num(qp_num);

        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn connect_qp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::ConnectQpRequest,
        sink: grpcio::UnarySink<proto::message::ConnectQpResponse>,
    ) {
        let ib_port = req.get_ib_port_num();
        let local_qp_map = QP_MAP.read().unwrap();
        let qp = local_qp_map.get(req.get_qp_id().cast::<usize>()).unwrap();
        let flag = req.get_access_flag();
        let gid_idx = req.get_gid_idx();
        let remote_qp_num = req.get_remote_qp_num();
        let remote_lid = req.get_remote_lid();
        let remote_gid: [u8; 16] = req.get_remote_gid().try_into().unwrap();
        let timeout = req.get_timeout();
        let retry_cnt = req.get_retry();
        let rnr_retry = req.get_rnr_retry();
        let mtu = req.get_mtu();
        let sq_start_psn = req.get_sq_start_psn();
        let rq_start_psn = req.get_rq_start_psn();
        let max_rd_atomic = req.get_max_rd_atomic();
        let max_dest_rd_atomic = req.get_max_dest_rd_atomic();
        let min_rnr_timer = req.get_min_rnr_timer();

        rdma::ibv::modify_qp_to_init(ib_port.cast(), *qp, rdma_sys::ibv_access_flags(flag.cast()));
        rdma::ibv::modify_qp_to_rtr(
            gid_idx.cast(),
            ib_port.cast(),
            *qp,
            remote_qp_num,
            remote_lid.cast(),
            u128::from_be_bytes(remote_gid),
            mtu,
            rq_start_psn,
            max_dest_rd_atomic.cast(),
            min_rnr_timer.cast(),
        );
        debug!(
            "Transfer to RTS, qp = {:?}, timeout = {}, retry_cnt = {}, rnr_retry = {}",
            (*qp).inner,
            timeout,
            retry_cnt,
            rnr_retry
        );
        rdma::ibv::modify_qp_to_rts(
            *qp,
            timeout.cast(),
            retry_cnt.cast(),
            rnr_retry.cast(),
            sq_start_psn,
            max_rd_atomic.cast(),
        );

        let resp = ConnectQpResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn remote_read(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteReadRequest,
        sink: grpcio::UnarySink<proto::message::RemoteReadResponse>,
    ) {
        rdma::ibv::remote_read(
            req.get_addr(),
            req.get_len(),
            req.get_lkey(),
            req.get_remote_addr(),
            req.get_remote_key(),
            *QP_MAP
                .read()
                .unwrap()
                .get(req.get_qp_id().cast::<usize>())
                .unwrap(),
            CQ_MAP
                .read()
                .unwrap()
                .get(req.get_cq_id().cast::<usize>())
                .unwrap()
                .0,
        );

        let resp = RemoteReadResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn remote_write(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteWriteRequest,
        sink: grpcio::UnarySink<proto::message::RemoteWriteResponse>,
    ) {
        rdma::ibv::remote_write(
            req.get_addr(),
            req.get_len(),
            req.get_lkey(),
            req.get_remote_addr(),
            req.get_remote_key(),
            *QP_MAP
                .read()
                .unwrap()
                .get(req.get_qp_id().cast::<usize>())
                .unwrap(),
            CQ_MAP
                .read()
                .unwrap()
                .get(req.get_cq_id().cast::<usize>())
                .unwrap()
                .0,
        );

        let resp = RemoteWriteResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn remote_atomic_cas(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteAtomicCasRequest,
        sink: grpcio::UnarySink<proto::message::RemoteAtomicCasResponse>,
    ) {
        rdma::ibv::remote_atomic_cas(
            req.addr,
            8,
            req.lkey,
            req.get_remote_addr(),
            req.get_remote_key(),
            req.old_value,
            req.new_value,
            *QP_MAP
                .read()
                .unwrap()
                .get(req.get_qp_id().cast::<usize>())
                .unwrap(),
            CQ_MAP
                .read()
                .unwrap()
                .get(req.get_cq_id().cast::<usize>())
                .unwrap()
                .0,
        );

        let resp = RemoteAtomicCasResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn local_recv(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::LocalRecvRequest,
        sink: grpcio::UnarySink<proto::message::LocalRecvResponse>,
    ) {
        rdma::ibv::post_receive(
            req.get_addr(),
            req.get_len(),
            req.get_lkey(),
            *QP_MAP
                .read()
                .unwrap()
                .get(req.get_qp_id().cast::<usize>())
                .unwrap(),
        );

        let resp = LocalRecvResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn poll_complete(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::PollCompleteRequest,
        sink: grpcio::UnarySink<proto::message::PollCompleteResponse>,
    ) {
        let (_, cqe) = rdma::ibv::poll_completion(
            CQ_MAP
                .read()
                .unwrap()
                .get(req.get_cq_id().cast::<usize>())
                .unwrap()
                .0,
        );

        let mut same = true;
        if req.has_sqpn() {
            same = same && cqe.src_qp == req.get_sqpn();
        }

        if req.has_qpn() {
            same = same && cqe.qp_num == req.get_qpn();
        }

        if req.has_len() {
            same = same && cqe.byte_len == req.get_len();
        }

        if req.has_opcode() {
            same = same && cqe.opcode == req.get_opcode();
        }

        if req.has_status() {
            same = same && cqe.status == req.get_status();
        }

        if req.has_imm_data_or_inv_rkey() {
            same = same
                && unsafe { cqe.imm_data_invalidated_rkey_union.invalidated_rkey }
                    == req.get_imm_data_or_inv_rkey();
        }

        let mut resp = PollCompleteResponse::default();
        resp.set_same(same);
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f)
    }

    fn remote_send(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::RemoteSendRequest,
        sink: grpcio::UnarySink<proto::message::RemoteSendResponse>,
    ) {
        rdma::ibv::remote_send(
            req.get_addr(),
            req.get_len(),
            req.get_lkey(),
            *QP_MAP
                .read()
                .unwrap()
                .get(req.get_qp_id().cast::<usize>())
                .unwrap(),
            CQ_MAP
                .read()
                .unwrap()
                .get(req.get_cq_id().cast::<usize>())
                .unwrap()
                .0,
        );

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

    fn query_port(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::QueryPortRequest,
        sink: grpcio::UnarySink<proto::message::QueryPortResponse>,
    ) {
        debug!("device name is {}", req.dev_name);
        let local_dev_map = DEV_MAP.read().unwrap();
        let ibv_ctx = local_dev_map.get(&req.dev_name).unwrap();
        let port_attr = rdma::ibv::query_port(*ibv_ctx, req.ib_port_num.cast());

        let mut resp = QueryPortResponse::default();
        resp.set_lid(port_attr.lid.cast());
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn query_gid(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::QueryGidRequest,
        sink: grpcio::UnarySink<proto::message::QueryGidResponse>,
    ) {
        let local_dev_map = DEV_MAP.read().unwrap();
        let ibv_ctx = local_dev_map.get(&req.dev_name).unwrap();
        let gid = rdma::ibv::query_gid(*ibv_ctx, req.ib_port_num.cast(), req.gid_idx.cast());

        let mut resp = QueryGidResponse::default();
        resp.set_gid_raw(unsafe { gid.raw }.to_vec());
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn local_write(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::LocalWriteRequest,
        sink: grpcio::UnarySink<proto::message::LocalWriteResponse>,
    ) {
        let mut local_mr_map = MR_MAP.write().unwrap();
        let mem = local_mr_map
            .get_mut(req.get_mr_id().cast::<usize>())
            .unwrap();

        let offset: usize = req.get_offset().cast();
        let len: usize = req.get_len().cast();

        let vec = &mut (*mem).deref_mut()[offset..(offset + len)];
        debug!(
            "local len {}, new content len {}",
            vec.len(),
            req.get_content().len()
        );
        vec.clone_from_slice(req.get_content());

        let resp = LocalWriteResponse::default();
        let f = sink.success(resp).map_err(|_| {}).map(|_| ());
        ctx.spawn(f);
    }

    fn local_check_mem(
        &mut self,
        ctx: grpcio::RpcContext,
        req: proto::message::LocalCheckMemRequest,
        sink: grpcio::UnarySink<proto::message::LocalCheckMemResponse>,
    ) {
        let mut local_mr_map = MR_MAP.write().unwrap();
        let mem = local_mr_map
            .get_mut(req.get_mr_id().cast::<usize>())
            .unwrap();

        let offset = req.get_offset();
        let expected = req.get_expected();

        let is_eq = offset
            .iter()
            .zip(expected)
            .map(|(off, content)| -> bool {
                let off_usize: usize = (*off).cast();
                let value = &(**mem)[off_usize..(off_usize + content.len())];
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
}
