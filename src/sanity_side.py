from proto.message_pb2 import ConnectQpResponse, CreateCqResponse, CreateMrResponse, CreatePdResponse, CreateQpResponse, LocalCheckMemResponse, LocalWriteResponse, OpenDeviceResponce, QueryPortResponse, RemoteReadRequest, VersionResponse, QueryGidResponse
from proto.side_pb2_grpc import SideServicer, add_SideServicer_to_server
from concurrent import futures
import grpc
from sys import argv
from roce_enum import ACCESS_FLAGS, SEND_FLAGS, WR_OPCODE
from roce_v2 import RoCEv2, SG, SendWR, QPS
from threading import Lock

GLOBAL_ROCE = RoCEv2()
pd_lock = Lock()
pd_list = []
mr_lock = Lock()
mr_list = []
cq_lock = Lock()
cq_list = []
qp_lock = Lock()
qp_list = []

class SanitySide(SideServicer):
    def __init__(self, ip):
        self.ip = ip

    def Version(self, request, context):
        return VersionResponse(version='0.1')

    def OpenDevice(self, request, context):
        print('request device name is {}'.format(request.dev_name))
        return OpenDeviceResponce(dev_name="dev_name")

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
        mr = pd.reg_mr(va=0x0000000000000000, length=request.len,
                       access_flags=(request.flag | ACCESS_FLAGS.ZERO_BASED))
        pd_lock.release()

        mr_lock.acquire()
        mr_list.append(mr)
        mr_id = len(mr_list) - 1
        mr_lock.release()

        return CreateMrResponse(addr=mr.va, len=mr.length, rkey=mr.remote_key, lkey=mr.local_key, mr_id=mr_id)

    def CreateCq(self, request, context):
        cq = GLOBAL_ROCE.create_cq()
        cq_lock.acquire()
        cq_list.append(cq)
        cq_id = len(cq_list) - 1
        cq_lock.release()

        return CreateCqResponse(cq_id = cq_id)

    def CreateQp(self, request, context):
        pd = pd_list[request.pd_id]
        cq = cq_list[request.cq_id]
        qp = GLOBAL_ROCE.create_qp(pd, cq, 15 | ACCESS_FLAGS.ZERO_BASED)
        qp_lock.acquire()
        qp_list.append(qp)
        qp_id = len(qp_list) - 1
        qp_lock.release()

        return CreateQpResponse(qp_id = qp_id, qp_num = qp.qpn())
    
    def ConnectQp(self, request, context):
        qp = qp_list[request.qp_id]
        qp.modify_qp(qps = QPS.RTS, access_flags = (request.access_flag | ACCESS_FLAGS.ZERO_BASED), dgid = request.remote_gid, dst_qpn = request.remote_qp_num, timeout = request.timeout, retry_cnt = request.retry, rnr_rery = request.rnr_retry)
        return ConnectQpResponse()

    def LocalWrite(self, request, context):
        mr = mr_list[request.mr_id]
        mr.write(request.content, request.offset)
        return LocalWriteResponse()
    
    def RemoteRead(self, request, context):
        sg = SG(pos_in_mr = request.addr, length = request.len, lkey = request.lkey)
        sr = SendWR(opcode = WR_OPCODE.RDMA_READ, sgl = sg, send_flags=SEND_FLAGS.SIGNALED, rmt_va = request.remote_addr, rkey = request.remote_key)
        qp = qp_list[request.qp_id]
        qp.post_send(sr)
        qp.process_one_sr()
        GLOBAL_ROCE.recv_pkts(1)
        cqe = qp.poll_cq()
        return RemoteReadRequest()

    def LocalCheckMem(self, request, context):
        mr = mr_list[request.mr_id]
        read = mr.byte_data[request.offset: (request.offset + request.len)]
        return LocalCheckMemResponse(same = (bytearray(request.expected) == read))

    def QueryPort(self, request, context):
        # Seem the lid is not required in the protocol
        return QueryPortResponse(lid = 1)

    def QueryGid(self, request, context):
        return QueryGidResponse(gid_raw = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + bytes(map(int, self.ip.split('.'))))

if __name__ == "__main__":
    ip_addr = argv[1]
    port = argv[2]
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_SideServicer_to_server(SanitySide(ip_addr), server)
    server.add_insecure_port('[::]:{}'.format(port))
    server.start()
    server.wait_for_termination()