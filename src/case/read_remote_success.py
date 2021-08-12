from proto.side_pb2_grpc import SideStub
from .base import TestCase
from config import Side
from proto import message_pb2, message_pb2_grpc
import threading
import time


class SideInfo:
    def __init__(self, dev_name, lid, gid, cq_id, pd_id, addr, len, rkey, lkey, qp_id, qp_num, mr_id):
        self.dev_name = dev_name
        self.lid = lid
        self.gid = gid
        self.cq_id = cq_id
        self.pd_id = pd_id
        self.addr = addr
        self.len = len
        self.rkey = rkey
        self.lkey = lkey
        self.qp_id = qp_id
        self.qp_num = qp_num
        self.mr_id = mr_id


class ReadRemoteSuccess(TestCase):
    def __init__(self, stub1: SideStub, stub2: SideStub, side1: Side, side2: Side):
        TestCase.__init__(self, stub1, stub2, side1, side2)

    def run(self):
        side_info_1 = prepare(self.side1, self.stub1)
        side_info_2 = prepare(self.side2, self.stub2)

        th1 = threading.Thread(target=be_read_side, args=(
            side_info_1, side_info_2, self.side1, self.stub1))
        th2 = threading.Thread(target=read_side, args=(
            side_info_2, side_info_1, self.side2, self.stub2))

        th1.start()
        th2.start()

        th1.join()
        th2.join()


def read_side(self_info: SideInfo, other_info: SideInfo, side: Side, stub: SideStub):
    stub.ConnectQp(message_pb2.ConnectQpRequest(
        dev_name=self_info.dev_name, qp_id=self_info.qp_id, access_flag=15, gid_idx=side.gid_idx(), ib_port_num=side.ib_port(), remote_qp_num=other_info.qp_num, remote_lid=other_info.lid, remote_gid=other_info.gid, timeout=0x12, retry=6, rnr_retry=0))
    time.sleep(1)
    stub.RemoteRead(message_pb2.RemoteReadRequest(addr=self_info.addr, len=2, lkey=self_info.lkey,
                    remote_addr=other_info.addr, remote_key=other_info.rkey, qp_id=self_info.qp_id, cq_id=self_info.cq_id))
    time.sleep(1)
    resp = stub.LocalCheckMem(message_pb2.LocalCheckMemRequest(mr_id = self_info.mr_id, offset = 0, len = 1, expected = b'\xff'))

    if resp.same:
        print("Value is read correctly")
    else:
        print("Value is NOT read correctly")


def be_read_side(self_info: SideInfo, other_info: SideInfo, side: Side, stub: SideStub):
    stub.ConnectQp(message_pb2.ConnectQpRequest(
        dev_name=self_info.dev_name, qp_id=self_info.qp_id, access_flag=15, gid_idx=side.gid_idx(), ib_port_num=side.ib_port(), remote_qp_num=other_info.qp_num, remote_lid=other_info.lid, remote_gid=other_info.gid, timeout=0x12, retry=6, rnr_retry=0))
    stub.LocalWrite(message_pb2.LocalWriteRequest(mr_id = self_info.mr_id, offset = 0, len = 1, content = b'\xff'))


def prepare(side: Side, stub: SideStub):
    dev_name = side.dev_name()
    dev_name = dev_name if dev_name else ''
    response = stub.OpenDevice(
        message_pb2.OpenDeviceRequest(dev_name=dev_name))
    dev_name = response.dev_name
    print("device name is {}".format(dev_name))

    response = stub.QueryPort(message_pb2.QueryPortRequest(
        dev_name=dev_name, ib_port_num=side.ib_port()))
    lid = response.lid

    response = stub.QueryGid(message_pb2.QueryGidRequest(
        dev_name=dev_name, ib_port_num=side.ib_port(), gid_idx=side.gid_idx()))

    gid = response.gid_raw

    response = stub.CreateCq(message_pb2.CreateCqRequest(
        dev_name=dev_name, cq_size=10))
    cq_id = response.cq_id

    response = stub.CreatePd(
        message_pb2.CreatePdRequest(dev_name=dev_name))
    pd_id = response.pd_id

    response = stub.CreateMr(
        message_pb2.CreateMrRequest(pd_id=pd_id, len=1024, flag=15))
    addr = response.addr
    len = response.len
    rkey = response.rkey
    lkey = response.lkey
    mr_id = response.mr_id

    response: message_pb2.CreateQpResponse = stub.CreateQp(
        message_pb2.CreateQpRequest(pd_id=pd_id, qp_type=0, cq_id=cq_id))
    qp_id = response.qp_id
    qp_num = response.qp_num

    return SideInfo(dev_name, lid, gid, cq_id, pd_id, addr, len, rkey, lkey, qp_id, qp_num, mr_id)
