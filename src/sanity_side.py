from proto.message_pb2 import (
    CheckQpStatusResponse,
    ConnectQpResponse,
    CreateCqResponse,
    CreateMrResponse,
    CreatePdResponse,
    CreateQpResponse,
    LocalCheckMemResponse,
    LocalRecvResponse,
    LocalWriteResponse,
    ModifyQpResponse,
    NotifyCqResponse,
    OpenDeviceResponce,
    PollCompleteResponse,
    QueryPortResponse,
    RecvPktResponse,
    RemoteAtomicCasResponse,
    RemoteReadResponse,
    RemoteSendResponse,
    RemoteWriteImmResponse,
    RemoteWriteResponse,
    UnblockRetryResponse,
    VersionResponse,
    QueryGidResponse,
    SetHookRequest,
    SetHookResponse,
)
from proto.side_pb2_grpc import SideServicer, add_SideServicer_to_server
from concurrent import futures
import grpc
from sys import argv
from roce_enum import ACCESS_FLAGS, SEND_FLAGS, WR_OPCODE
from roce_v2 import RecvWR, RoCEv2, SG, SendWR, QPS
from threading import Lock
from functools import partial
import time
import logging
import pickle
from roce import (
    GRH,
    AETH,
    RETH,
    AtomicAckETH,
    AtomicETH,
    ImmDt,
    IETH,
    RETHImmDt,
    CNPPadding,
    BTH,
)

GLOBAL_ROCE = RoCEv2()
pd_lock = Lock()
pd_list = []
mr_lock = Lock()
mr_list = []
cq_lock = Lock()
cq_list = []
qp_lock = Lock()
qp_list = []
retry_lock = Lock()
retry_count = 0


class SanitySide(SideServicer):
    def __init__(self, ip):
        self.ip = ip

    def Version(self, request, context):
        return VersionResponse(version="0.1")

    def OpenDevice(self, request, context):
        logging.debug("request device name is {}".format(request.dev_name))
        return OpenDeviceResponce(dev_name="sim")

    def CreatePd(self, request, context):
        pd = GLOBAL_ROCE.alloc_pd()
        pd_lock.acquire()
        pd_list.append(pd)
        pd_id = len(pd_list) - 1
        pd_lock.release()
        return CreatePdResponse(pd_id=pd_id)

    def CreateMr(self, request, context):
        pd_id = request.pd_id
        pd = pd_list[pd_id]
        pd_lock.acquire()  # TODO: Make pd method thread-safe
        # TODO: Make the va different on different request
        mr = pd.reg_mr(
            va=0x0000000000000000,
            length=request.len,
            access_flags=(request.flag | ACCESS_FLAGS.ZERO_BASED),
        )
        pd_lock.release()

        mr_lock.acquire()
        mr_list.append(mr)
        mr_id = len(mr_list) - 1
        mr_lock.release()

        return CreateMrResponse(
            addr=mr.va,
            len=mr.length,
            rkey=mr.remote_key,
            lkey=mr.local_key,
            mr_id=mr_id,
        )

    def CreateCq(self, request, context):
        cq = GLOBAL_ROCE.create_cq()
        cq_lock.acquire()
        cq_list.append(cq)
        cq_id = len(cq_list) - 1
        cq_lock.release()

        return CreateCqResponse(cq_id=cq_id)

    def CreateQp(self, request, context):
        pd = pd_list[request.pd_id]
        cq = cq_list[request.cq_id]
        qp = GLOBAL_ROCE.create_qp(pd, cq, 15 | ACCESS_FLAGS.ZERO_BASED)
        qp_lock.acquire()
        qp_list.append(qp)
        qp_id = len(qp_list) - 1
        qp_lock.release()

        return CreateQpResponse(qp_id=qp_id, qp_num=qp.qpn())

    def ConnectQp(self, request, context):
        qp = qp_list[request.qp_id]
        qp.modify_qp(
            qps=QPS.RTS,
            access_flags=(request.access_flag | ACCESS_FLAGS.ZERO_BASED),
            dgid=request.remote_gid,
            dst_qpn=request.remote_qp_num,
            timeout=request.timeout,
            retry_cnt=request.retry,
            rnr_retry=request.rnr_retry,
            pmtu=request.mtu,
            rq_psn=request.rq_start_psn,
            sq_psn=request.sq_start_psn,
            max_rd_atomic=request.max_rd_atomic,
            max_dest_rd_atomic=request.max_dest_rd_atomic,
            min_rnr_timer=request.min_rnr_timer,
        )
        return ConnectQpResponse()

    def LocalWrite(self, request, context):
        mr = mr_list[request.mr_id]
        mr.write(request.content, request.offset)
        return LocalWriteResponse()

    def UnblockRetry(self, request, context):
        global retry_count, retry_lock
        while retry_count == 0:
            time.sleep(0.1)
        with retry_lock:
            retry_count -= 1
        return UnblockRetryResponse()

    def RemoteRead(self, request, context):
        sg = SG(pos_in_mr=request.addr, length=request.len, lkey=request.lkey)
        sr = SendWR(
            opcode=WR_OPCODE.RDMA_READ,
            sgl=sg,
            send_flags=SEND_FLAGS.SIGNALED,
            rmt_va=request.remote_addr,
            rkey=request.remote_key,
        )
        qp = qp_list[request.qp_id]
        qp.post_send(sr)
        qp.process_one_sr(request.real_send)
        return RemoteReadResponse()

    def RemoteWrite(self, request, context):
        sg = SG(pos_in_mr=request.addr, length=request.len, lkey=request.lkey)
        sr = SendWR(
            opcode=WR_OPCODE.RDMA_WRITE,
            sgl=sg,
            send_flags=SEND_FLAGS.SIGNALED,
            rmt_va=request.remote_addr,
            rkey=request.remote_key,
        )
        qp = qp_list[request.qp_id]
        qp.post_send(sr)
        qp.process_one_sr()
        return RemoteWriteResponse()

    def RemoteWriteImm(self, request, context):
        sg = SG(pos_in_mr=request.addr, length=request.len, lkey=request.lkey)
        sr = SendWR(
            opcode=WR_OPCODE.RDMA_WRITE_WITH_IMM,
            sgl=sg,
            send_flags=request.send_flag,
            rmt_va=request.remote_addr,
            rkey=request.remote_key,
            imm_data_or_inv_rkey=request.imm_data,
        )
        qp = qp_list[request.qp_id]
        qp.post_send(sr)
        qp.process_one_sr()
        return RemoteWriteImmResponse()

    def RemoteSend(self, request, context):
        sg = SG(pos_in_mr=request.addr, length=request.len, lkey=request.lkey)
        sr = SendWR(opcode=WR_OPCODE.SEND, sgl=sg, send_flags=SEND_FLAGS.SIGNALED)
        qp = qp_list[request.qp_id]
        qp.post_send(sr)
        qp.process_one_sr()
        return RemoteSendResponse()

    def RemoteAtomicCas(self, request, context):
        sg = SG(pos_in_mr=request.addr, length=8, lkey=request.lkey)
        sr = SendWR(
            opcode=WR_OPCODE.ATOMIC_CMP_AND_SWP,
            sgl=sg,
            send_flags=SEND_FLAGS.SIGNALED,
            rmt_va=request.remote_addr,
            rkey=request.remote_key,
            compare_add=request.old_value,
            swap=request.new_value,
        )
        qp = qp_list[request.qp_id]
        qp.post_send(sr)
        qp.process_one_sr()
        return RemoteAtomicCasResponse()

    def RecvPkt(self, request, context):
        pkt_check_result = True

        def check(ck_list, pkt):
            for ck in ck_list:
                header = ck.get("header")
                field = ck.get("field")
                expect = ck.get("expect")
                if not header:
                    logging.error("header should be set in recv_pkt check list")
                    pkt_check_result = False
                    break
                if not field:
                    logging.error("field should be set in recv_pkt check list")
                    pkt_check_result = False
                    break
                header_class = globals().get(header)
                if not header_class:
                    logging.error(f"{header} is not a defined HEADER")
                    pkt_check_result = False
                    break
                if not hasattr(pkt[header_class], field):
                    logging.error(f"{field} is not defined in {header} HEADER")
                    pkt_check_result = False
                    break
                if expect != getattr(pkt[header_class], field):
                    logging.error(
                        f"{header}.{field} is {getattr(pkt[header_class], field)}, but expect {expect}"
                    )
                    pkt_check_result = False
                    break

        check_fun = None
        if request.HasField("check_pkt"):
            check_pkt = pickle.loads(request.check_pkt)
            check_fun = partial(check, check_pkt)

        retry_handler = (
            partial(default_retry_handler, request.wait_for_retry)
            if request.wait_for_retry
            else None
        )
        qp = qp_list[request.qp_id]
        opcode = qp.rq.recv_pkts(
            request.cnt,
            retry_handler=retry_handler,
            check_pkt=check_fun,
            real_recv=request.real_recv,
        )[-1]
        if request.poll_cqe:
            qp.poll_cq()
        return RecvPktResponse(opcode=opcode, check_pass=pkt_check_result)

    def ModifyQp(self, request, context):
        qp = qp_list[request.qp_id]
        qp.modify_qp(sq_psn=request.sq_psn)
        return ModifyQpResponse()

    def LocalCheckMem(self, request, context):
        mr = mr_list[request.mr_id]
        offset = request.offset
        expected = request.expected

        result = True
        for i in range(len(offset)):
            read = mr.byte_data[offset[i] : (offset[i] + len(expected[i]))]
            logging.debug(f"local check real data {read} for offset {offset[i]}")
            result = result and (bytearray(expected[i]) == read)
        return LocalCheckMemResponse(same=result)

    def LocalRecv(self, request, context):
        qp = qp_list[request.qp_id]
        sg = SG(pos_in_mr=request.addr, length=request.len, lkey=request.lkey)
        rr = RecvWR(sgl=sg)
        qp.post_recv(rr)
        qp.modify_qp(qps=QPS.RTR)
        return LocalRecvResponse()

    def QueryPort(self, request, context):
        # Seem the lid is not required in the protocol
        return QueryPortResponse(lid=1)

    def QueryGid(self, request, context):
        return QueryGidResponse(
            gid_raw=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
            + bytes(map(int, self.ip.split(".")))
        )

    def PollComplete(self, request, context):
        qp = qp_list[request.qp_id]
        cqe = qp.poll_cq()

        same = True

        if request.HasField("sqpn"):
            same = same and cqe.sqpn() == request.sqpn

        if request.HasField("qpn"):
            same = same and cqe.local_qpn() == request.qpn

        if request.HasField("len"):
            same = same and cqe.len() == request.len

        if request.HasField("opcode"):
            same = same and cqe.op() == request.opcode

        if request.HasField("status"):
            same = same and cqe.status() == request.status

        if request.HasField("imm_data_or_inv_rkey"):
            same = same and cqe.imm_data_or_inv_rkey() == request.imm_data_or_inv_rkey

        return PollCompleteResponse(same=same)

    def CheckQpStatus(self, request, context):
        expect_status = request.status
        qp = qp_list[request.qp_id]
        return CheckQpStatusResponse(same=(qp.status() == expect_status))

    # Notify CQ is not implemented in the python side
    def NotifyCq(self, request, context):
        return NotifyCqResponse()

    def SetHook(self, request, context):
        import hooks

        try:
            hook = getattr(hooks, request.hook_name)
            qp = qp_list[request.qp_id]
            hook_type = request.hook_type
            if hook_type == hooks.HOOK_TYPE.SEND:
                qp.sq.reg_send_hook(hook)
            elif hook_type == hooks.HOOK_TYPE.RECV:
                qp.reg_recv_hook(hook)
            elif hook_type == hooks.HOOK_TYPE.RESP:
                qp.rq.reg_resp_hook(hook)
            else:
                logging.error(f"wrong hook type {request.hook_type}")
                return SetHookResponse(is_success=False)
            return SetHookResponse(is_success=True)
        except:
            logging.error(f"can not find hook fn {request.hook_name}")
            return SetHookResponse(is_success=False)


def default_retry_handler(barrier_cnt):
    global retry_count, retry_lock
    logging.debug("Block")
    with retry_lock:
        retry_count += barrier_cnt

    while retry_count:
        time.sleep(1)

    logging.debug("Get unblock signal")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    ip_addr = argv[1]
    port = argv[2]
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_SideServicer_to_server(SanitySide(ip_addr), server)
    server.add_insecure_port("[::]:{}".format(port))
    server.start()
    server.wait_for_termination()
