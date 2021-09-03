from proto.side_pb2_grpc import SideStub
from .base import TestCase, SideInfo, prepare
from config import Side
from proto import message_pb2 
import threading
import time

class SendRnrRetry(TestCase):
    def __init__(self, stub1: SideStub, stub2: SideStub, side1: Side, side2: Side):
        TestCase.__init__(self, stub1, stub2, side1, side2)

    def run(self):
        side_info_1 = prepare(self.side1, self.stub1)
        side_info_2 = prepare(self.side2, self.stub2)

        th1 = threading.Thread(target=recv_side, args=(
            side_info_1, side_info_2, self.side1, self.stub1, self.stub2))
        th2 = threading.Thread(target=send_side, args=(
            side_info_2, side_info_1, self.side2, self.stub2))

        th1.start()
        th2.start()

        th1.join()
        th2.join()


def send_side(self_info: SideInfo, other_info: SideInfo, side: Side, stub: SideStub):
    stub.ConnectQp(message_pb2.ConnectQpRequest(
        dev_name=self_info.dev_name, qp_id=self_info.qp_id, access_flag=15, gid_idx=side.gid_idx(), ib_port_num=side.ib_port(), remote_qp_num=other_info.qp_num, remote_lid=other_info.lid, remote_gid=other_info.gid, timeout=14, retry=7, rnr_retry=7))
    stub.LocalWrite(message_pb2.LocalWriteRequest(
        mr_id=self_info.mr_id, offset=0, len=1, content=b'\xff'))
    stub.RemoteSend(message_pb2.RemoteSendRequest(addr=self_info.addr, len=2, lkey=self_info.lkey,
                    qp_id=self_info.qp_id, cq_id=self_info.cq_id))

    # Retry
    stub.RecvPkt(message_pb2.RecvPktRequest(
        wait_for_retry=True, has_cqe=True, qp_id=self_info.qp_id))
    # Handle success
    stub.RecvPkt(message_pb2.RecvPktRequest(
        wait_for_retry=True, has_cqe=True, qp_id=self_info.qp_id))

def recv_side(self_info: SideInfo, other_info: SideInfo, side: Side, stub: SideStub, other_stub: SideStub):
    stub.ConnectQp(message_pb2.ConnectQpRequest(
        dev_name=self_info.dev_name, qp_id=self_info.qp_id, access_flag=15, gid_idx=side.gid_idx(), ib_port_num=side.ib_port(), remote_qp_num=other_info.qp_num, remote_lid=other_info.lid, remote_gid=other_info.gid, timeout=14, retry=7, rnr_retry=7))
    
    other_stub.UnblockRetry(message_pb2.UnblockRetryRequest())
    stub.LocalRecv(message_pb2.LocalRecvRequest(addr=self_info.addr, len=2,
                   lkey=self_info.lkey, qp_id=self_info.qp_id, cq_id=self_info.cq_id))
    
    time.sleep(2)
    resp = stub.LocalCheckMem(message_pb2.LocalCheckMemRequest(
        mr_id=self_info.mr_id, offset=0, len=1, expected=b'\xff'))

    if resp.same:
        print("Value is read correctly")
    else:
        print("Value is NOT read correctly")


