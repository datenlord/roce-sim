from config import Side
from proto.side_pb2_grpc import SideStub
from proto import message_pb2

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

class TestCase:
    def __init__(self, stub1: SideStub, stub2: SideStub, side1: Side, side2: Side):
        self.stub1 = stub1
        self.stub2 = stub2
        self.side1 = side1
        self.side2 = side2

    def run(self):
        pass

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