from config import Side
from proto.side_pb2_grpc import SideStub
from proto import message_pb2
from typing import Final
from collections import Mapping
import os
import yaml
import concurrent.futures
import time

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class SideInfo:
    def __init__(
        self,
        dev_name,
        lid,
        gid,
        cq_id,
        pd_id,
        addr,
        len,
        rkey,
        lkey,
        qp_id,
        qp_num,
        mr_id,
    ):
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
    TEST_DEF_DIR_ENV: Final = "TEST_DEF_DIR"
    DEFAULT_TEST_DEF_DIR: Final = "./case"

    def __init__(self, stub1: SideStub, stub2: SideStub, side1: Side, side2: Side):
        self.stub1 = stub1
        self.stub2 = stub2
        self.side1 = side1
        self.side2 = side2

    def run(self, test_name):
        info1 = prepare(self.side1, self.stub1)
        info2 = prepare(self.side2, self.stub2)
        test_def_dir = os.getenv(TestCase.TEST_DEF_DIR_ENV)
        if not test_def_dir:
            test_def_dir = TestCase.DEFAULT_TEST_DEF_DIR
        test_file_name = "{}/{}.yaml".format(test_def_dir, test_name)
        test = None
        try:
            test = yaml.load(open(test_file_name, "r"), Loader=Loader)
        except Exception as e:
            print(f"Error to parse test file {test_file_name}")
            raise e

        side1_cmd = test.get("side_1")
        side2_cmd = test.get("side_2")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            cmd_future = []
            future2side = {}
            if side1_cmd:
                tmp_future = executor.submit(
                    process_command,
                    side1_cmd,
                    self.side1,
                    info1,
                    self.stub1,
                    self.side2,
                    info2,
                    self.stub2,
                )
                future2side[tmp_future] = "side_1"
                cmd_future.append(tmp_future)
            if side2_cmd:
                tmp_future = executor.submit(
                    process_command,
                    side2_cmd,
                    self.side2,
                    info2,
                    self.stub2,
                    self.side1,
                    info1,
                    self.stub1,
                )
                future2side[tmp_future] = "side_2"
                cmd_future.append(tmp_future)

            for f in concurrent.futures.as_completed(cmd_future):
                try:
                    if not f.result():
                        print(f"{future2side[f]} command failed")
                except Exception as e:
                    print(
                        f"get an exception from {future2side[f]} command: {format(e)}"
                    )


def connect_qp(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    timeout = c_arg.get("timeout", 14)
    retry = c_arg.get("retry", 7)
    rnr_retry = c_arg.get("rnr_retry", 7)
    self_stub.ConnectQp(
        message_pb2.ConnectQpRequest(
            dev_name=self_info.dev_name,
            qp_id=self_info.qp_id,
            access_flag=15,
            gid_idx=self_side.gid_idx(),
            ib_port_num=self_side.ib_port(),
            remote_qp_num=other_info.qp_num,
            remote_lid=other_info.lid,
            remote_gid=other_info.gid,
            timeout=timeout,
            retry=retry,
            rnr_retry=rnr_retry,
        )
    )
    return True


def sleep(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    len = c_arg.get("len")
    time.sleep(len)
    return True


def recv_pkt(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    retry = c_arg.get("wait_for_retry", False)
    self_stub.RecvPkt(
        message_pb2.RecvPktRequest(
            wait_for_retry=retry, has_cqe=True, qp_id=self_info.qp_id
        )
    )
    return True


def local_check(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    expected = c_arg.get("expected")
    if not expected:
        print("should set expected in local_check")
        return False
    expected = bytes.fromhex(expected)

    resp = self_stub.LocalCheckMem(
        message_pb2.LocalCheckMemRequest(
            mr_id=self_info.mr_id, offset=offset, len=len(expected), expected=expected
        )
    )
    if resp.same:
        print("value read correct")
    else:
        print("value read INCORRECT")
    return resp.same


def local_write(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    content = c_arg.get("content")
    if not content:
        print("should set content in local_write")
        return False
    content = bytes.fromhex(content)
    self_stub.LocalWrite(
        message_pb2.LocalWriteRequest(
            mr_id=self_info.mr_id, offset=offset, len=len(content), content=content
        )
    )
    return True


def remote_read(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    local_offset = c_arg.get("local_offset", 0)
    remote_offset = c_arg.get("remote_offset", 0)
    len = c_arg.get("len", 0)

    self_stub.RemoteRead(
        message_pb2.RemoteReadRequest(
            addr=(self_info.addr + local_offset),
            len=len,
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def remote_write(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    local_offset = c_arg.get("local_offset", 0)
    remote_offset = c_arg.get("remote_offset", 0)
    len = c_arg.get("len", 0)

    self_stub.RemoteWrite(
        message_pb2.RemoteWriteRequest(
            addr=(self_info.addr + local_offset),
            len=len,
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def remote_send(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    len = c_arg.get("len", 0)

    self_stub.RemoteSend(
        message_pb2.RemoteSendRequest(
            addr=(self_info.addr + offset),
            len=len,
            lkey=self_info.lkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def remote_atomic_cas(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    remote_offset = c_arg.get("remote_offset", 0)
    old_value = c_arg.get("old_value")
    new_value = c_arg.get("new_value")

    if not old_value:
        print("old_value should be set")
        return False

    if not new_value:
        print("new_value should be set")
        return False

    self_stub.RemoteAtomicCas(
        message_pb2.RemoteAtomicCasRequest(
            addr=(self_info.addr + offset),
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            old_value=old_value,
            new_value=new_value,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )

    return True


def local_recv(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    len = c_arg.get("len", 0)

    self_stub.LocalRecv(
        message_pb2.LocalRecvRequest(
            addr=(self_info.addr + offset),
            len=len,
            lkey=self_info.lkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def unblock_other(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    other_stub.UnblockRetry(message_pb2.UnblockRetryRequest())
    return True


COMMAND_MAP: Final = {
    "connect_qp": connect_qp,
    "sleep": sleep,
    "recv_pkt": recv_pkt,
    "local_check": local_check,
    "local_write": local_write,
    "remote_read": remote_read,
    "remote_write": remote_write,
    "remote_send": remote_send,
    "remote_atomic_cas": remote_atomic_cas,
    "local_recv": local_recv,
    "unblock_other": unblock_other,
}


def process_command(
    cmds,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    for c in cmds:
        if not c["name"]:
            print("command missing name")
            return False
        fun = COMMAND_MAP[c["name"]]
        if fun:
            try:
                if not fun(
                    c,
                    self_side,
                    self_info,
                    self_stub,
                    other_side,
                    other_info,
                    other_stub,
                ):
                    print(f'failed to executed command {c["name"]}')
                    return False
            except Exception as e:
                print(f'failed to executed command {c["name"]}, {e}')
                return False
        else:
            print(f'command {c["name"]} is not in the definition')
            return False
    return True


def prepare(side: Side, stub: SideStub):
    dev_name = side.dev_name()
    dev_name = dev_name if dev_name else ""
    response = stub.OpenDevice(message_pb2.OpenDeviceRequest(dev_name=dev_name))
    dev_name = response.dev_name
    print(f"device name is {dev_name}")

    response = stub.QueryPort(
        message_pb2.QueryPortRequest(dev_name=dev_name, ib_port_num=side.ib_port())
    )
    lid = response.lid

    response = stub.QueryGid(
        message_pb2.QueryGidRequest(
            dev_name=dev_name, ib_port_num=side.ib_port(), gid_idx=side.gid_idx()
        )
    )

    gid = response.gid_raw

    response = stub.CreateCq(message_pb2.CreateCqRequest(dev_name=dev_name, cq_size=10))
    cq_id = response.cq_id

    response = stub.CreatePd(message_pb2.CreatePdRequest(dev_name=dev_name))
    pd_id = response.pd_id

    response = stub.CreateMr(
        message_pb2.CreateMrRequest(pd_id=pd_id, len=1024, flag=15)
    )
    addr = response.addr
    len = response.len
    rkey = response.rkey
    lkey = response.lkey
    mr_id = response.mr_id

    response: message_pb2.CreateQpResponse = stub.CreateQp(
        message_pb2.CreateQpRequest(pd_id=pd_id, qp_type=0, cq_id=cq_id)
    )
    qp_id = response.qp_id
    qp_num = response.qp_num

    return SideInfo(
        dev_name, lid, gid, cq_id, pd_id, addr, len, rkey, lkey, qp_id, qp_num, mr_id
    )
