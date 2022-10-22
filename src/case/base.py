from functools import partial
from math import pi
from config import Side
from proto.side_pb2_grpc import SideStub
from proto import message_pb2
from typing import Final
from collections.abc import Mapping
import os
import yaml
import concurrent.futures
import time
import threading
import logging
import pickle
from roce_enum import RC, WC_OPCODE, WC_STATUS, QPS

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

GlobalBarrier = threading.Barrier(2, timeout=10)


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
        test_def_dir = os.getenv(TestCase.TEST_DEF_DIR_ENV)
        if not test_def_dir:
            test_def_dir = TestCase.DEFAULT_TEST_DEF_DIR
        if test_name[-5:] == ".yaml":
            test_file_name = test_name
        else:
            test_file_name = "{}/{}.yaml".format(test_def_dir, test_name)
        logging.info("test_case: {}".format(test_file_name))
        test = None
        try:
            test = yaml.load(open(test_file_name, "r"), Loader=Loader)
        except Exception as e:
            logging.error(f"Error to parse test file {test_file_name}")
            raise e

        side1_cmd = test.get("side_1")
        side2_cmd = test.get("side_2")

        try:
            info1, side1_cmd = prepare(side1_cmd, self.side1, self.stub1, False)
            info2, side2_cmd = prepare(side2_cmd, self.side2, self.stub2, True)
        except Exception as e:
            logging.error(
                f"Error when run prepare command for file {test_file_name}, {e}"
            )
            raise e

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            cmd_future = []
            future2side = {}
            if side1_cmd:
                tmp_future = executor.submit(
                    process_command,
                    test_name,
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
                    test_name,
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
                        logging.error(f"{future2side[f]} command failed")
                except Exception as e:
                    logging.error(
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
    retry = c_arg.get("retry", 3)
    rnr_retry = c_arg.get("rnr_retry", 3)
    qp_flag = c_arg.get("qp_flag", 15)
    mtu = c_arg.get("mtu", 1024)
    sq_start_psn = c_arg.get("sq_start_psn", 0)
    rq_start_psn = c_arg.get("rq_start_psn", 0)
    max_rd_atomic = c_arg.get("max_rd_atomic", 2)
    max_dest_rd_atomic = c_arg.get("max_dest_rd_atomic", 2)
    min_rnr_timer = c_arg.get("min_rnr_timer", 0x12)

    self_stub.ConnectQp(
        message_pb2.ConnectQpRequest(
            dev_name=self_info.dev_name,
            qp_id=self_info.qp_id,
            access_flag=qp_flag,
            gid_idx=self_side.gid_idx(),
            ib_port_num=self_side.ib_port(),
            remote_qp_num=other_info.qp_num,
            remote_lid=other_info.lid,
            remote_gid=other_info.gid,
            timeout=timeout,
            retry=retry,
            rnr_retry=rnr_retry,
            mtu=mtu,
            sq_start_psn=sq_start_psn,
            rq_start_psn=rq_start_psn,
            max_rd_atomic=max_rd_atomic,
            max_dest_rd_atomic=max_dest_rd_atomic,
            min_rnr_timer=min_rnr_timer,
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
    check_pkt = c_arg.get("check_pkt")
    retry = c_arg.get("wait_for_retry", 0)
    poll_cqe = c_arg.get("poll_cqe", True)
    cnt = c_arg.get("cnt", 1)
    real_recv = c_arg.get("real_recv", True)

    request = message_pb2.RecvPktRequest(
        wait_for_retry=retry,
        poll_cqe=poll_cqe,
        qp_id=self_info.qp_id,
        cnt=cnt,
        real_recv=real_recv,
    )

    if check_pkt:
        request.check_pkt = pickle.dumps(check_pkt)

    response = self_stub.RecvPkt(request)

    result = True
    expect_opcode = c_arg.get("opcode")
    if expect_opcode:
        if isinstance(expect_opcode, str):
            try:
                expect_opcode = RC[expect_opcode].value
            except Exception:
                logging.error(f"{expect_opcode} is not a valid rc opcode")
                return False
        result = result and expect_opcode == response.opcode

    if check_pkt:
        result = result and response.check_pass

    return result


def local_check(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = []
    expected = []
    for r in c_arg.get("seg"):
        offset.append(r.get("offset", 0))
        e = r.get("expected")
        if not e:
            logging.error("should set expected in local_check")
            return False
        expected.append(bytes.fromhex(e))

    resp = self_stub.LocalCheckMem(
        message_pb2.LocalCheckMemRequest(
            mr_id=self_info.mr_id, offset=offset, expected=expected
        )
    )
    if resp.same:
        logging.info("value read correct")
    else:
        logging.info("value read INCORRECT")
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
        logging.error("should set content in local_write")
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
    real_send = c_arg.get("real_send", True)
    allow_err = c_arg.get("allow_err", False)

    self_stub.RemoteRead(
        message_pb2.RemoteReadRequest(
            addr=(self_info.addr + local_offset),
            len=len,
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
            real_send=real_send,
            mr_id=self_info.mr_id,
            allow_err=allow_err,
            dev_name=self_info.dev_name,
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
    allow_err = c_arg.get("allow_err", False)

    self_stub.RemoteWrite(
        message_pb2.RemoteWriteRequest(
            addr=(self_info.addr + local_offset),
            len=len,
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
            mr_id=self_info.mr_id,
            allow_err=allow_err,
            dev_name=self_info.dev_name,
        )
    )
    return True


def remote_write_imm(
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
    imm = c_arg.get("imm", 0x1234)
    send_flag = c_arg.get("send_flag", 2)
    allow_err = c_arg.get("allow_err", False)

    if isinstance(send_flag, str):
        if send_flag == "SIGNALED":
            send_flag = 2
        elif send_flag == "SOLICITED":
            send_flag = 4
        else:
            logging.error(
                f"{send_flag} is not supported, only SIGNALED and SOLICITED is supported"
            )
            return False

    self_stub.RemoteWriteImm(
        message_pb2.RemoteWriteImmRequest(
            addr=(self_info.addr + local_offset),
            len=len,
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            imm_data=imm,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
            send_flag=send_flag,
            mr_id=self_info.mr_id,
            allow_err=allow_err,
            dev_name=self_info.dev_name,
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
    allow_err = c_arg.get("allow_err", False)

    self_stub.RemoteSend(
        message_pb2.RemoteSendRequest(
            addr=(self_info.addr + offset),
            len=len,
            lkey=self_info.lkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
            mr_id=self_info.mr_id,
            allow_err=allow_err,
            dev_name=self_info.dev_name,
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
    allow_err = c_arg.get("allow_err", False)

    if not old_value:
        logging.error("old_value should be set")
        return False

    if not new_value:
        logging.error("new_value should be set")
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
            allow_err=allow_err,
            dev_name=self_info.dev_name,
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
            mr_id=self_info.mr_id,
            dev_name=self_info.dev_name,
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


def barrier(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    GlobalBarrier.wait()
    return True


def poll_complete(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    request = message_pb2.PollCompleteRequest(
        qp_id=self_info.qp_id,
        cq_id=self_info.cq_id,
    )
    sqpn = c_arg.get("sqpn")
    if sqpn:
        request.sqpn = sqpn

    qpn = c_arg.get("qpn")
    if qpn:
        request.qpn = qpn

    len = c_arg.get("len")
    if len:
        request.len = len

    opcode = c_arg.get("opcode")
    if opcode:
        if isinstance(opcode, str):
            try:
                opcode = WC_OPCODE[opcode].value
            except Exception:
                logging.error(f"{opcode} is not a valid wc opcode")
                return False
        request.opcode = opcode

    status = c_arg.get("status")
    if status:
        if isinstance(status, str):
            try:
                status = WC_STATUS[status].value
            except Exception:
                logging.error(f"{status} is not a valid wc status")
                return False
        request.status = status

    imm_data_or_inv_rkey = c_arg.get("imm_data_or_inv_rkey")
    if imm_data_or_inv_rkey:
        request.imm_data_or_inv_rkey = imm_data_or_inv_rkey

    response = self_stub.PollComplete(request)
    return response.same


def check_qp_status(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    status = c_arg.get("status")
    if not status:
        logging.error("status should be set")
        return False

    if isinstance(status, str):
        try:
            status = QPS[status].value
        except Exception:
            logging.error(f"{status} is not a valid qp status")
            return False

    response = self_stub.CheckQpStatus(
        message_pb2.CheckQpStatusRequest(
            status=status, qp_id=self_info.qp_id, dev_name=self_info.dev_name
        )
    )
    return response.same


def modify_qp(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    sq_psn = c_arg.get("sq_psn")
    if sq_psn:
        response = self_stub.ModifyQp(
            message_pb2.ModifyQpRequest(qp_id=self_info.qp_id, sq_psn=sq_psn)
        )

    return True


def notify_cq(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    solicited_only = c_arg.get("solicited_only", False)
    response = self_stub.NotifyCq(
        message_pb2.NotifyCqRequest(
            cq_id=self_info.cq_id, solicited_only=1 if solicited_only else 0
        )
    )
    return True


HOOKS_MAP: Final = {
    "send": 0,
    "recv": 1,
    "resp": 2,
}


def set_hook(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    hook_type = HOOKS_MAP[c_arg.get("hook_type")]
    hook_name = c_arg.get("hook_name")

    return self_stub.SetHook(
        message_pb2.SetHookRequest(
            qp_id=self_info.qp_id, hook_type=hook_type, hook_name=hook_name
        )
    )


COMMAND_MAP: Final = {
    "connect_qp": connect_qp,
    "sleep": sleep,
    "recv_pkt": recv_pkt,
    "local_check": local_check,
    "local_write": local_write,
    "remote_read": remote_read,
    "remote_write": remote_write,
    "remote_write_imm": remote_write_imm,
    "remote_send": remote_send,
    "remote_atomic_cas": remote_atomic_cas,
    "local_recv": local_recv,
    "unblock_other": unblock_other,
    "barrier": barrier,
    "poll_complete": poll_complete,
    "check_qp_status": check_qp_status,
    "modify_qp": modify_qp,
    "notify_cq": notify_cq,
    "set_hook": set_hook,
}


def process_command(
    test_name,
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
            logging.error("command missing name")
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
                    logging.error(
                        f'failed to executed command {c["name"]} for case {test_name}'
                    )
                    return False
            except Exception as e:
                logging.error(
                    f'failed to executed command {c["name"]} for case {test_name}, exception: {repr(e)}'
                )
                return False
        else:
            logging.error(
                f'command {c["name"]} is not in the definition, for case {test_name}'
            )
            return False
    return True


def prepare(cmds, side: Side, stub: SideStub, is_py_side):
    first_cmd = cmds[0]
    if first_cmd["name"] != "prepare":
        raise RuntimeError(
            f"first command should be prepare, but it's {first_cmd['name']}"
        )

    mr_len = first_cmd.get("mr_len", 1024)
    mr_flag = first_cmd.get("mr_flag", 15)

    dev_name = side.dev_name()
    dev_name = dev_name if dev_name else ""

    if is_py_side:
        response = stub.OpenDevice(message_pb2.OpenDeviceRequest(dev_name=dev_name))
        dev_name = response.dev_name

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

        response = stub.CreateCq(
            message_pb2.CreateCqRequest(dev_name=dev_name, cq_size=10)
        )
        cq_id = response.cq_id

        response = stub.CreatePd(message_pb2.CreatePdRequest(dev_name=dev_name))
        pd_id = response.pd_id

        response = stub.CreateQp(
            message_pb2.CreateQpRequest(pd_id=pd_id, qp_type=0, cq_id=cq_id)
        )
        qp_id = response.qp_id
        qp_num = response.qp_num
    else:
        qp_cmd = cmds[1]

        timeout = qp_cmd.get("timeout", 14)
        retry = qp_cmd.get("retry", 3)
        rnr_retry = qp_cmd.get("rnr_retry", 3)
        qp_flag = qp_cmd.get("qp_flag", 15)
        mtu = qp_cmd.get("mtu", 1024)
        sq_start_psn = qp_cmd.get("sq_start_psn", 0)
        rq_start_psn = qp_cmd.get("rq_start_psn", 0)
        max_rd_atomic = qp_cmd.get("max_rd_atomic", 2)
        max_dest_rd_atomic = qp_cmd.get("max_dest_rd_atomic", 2)
        min_rnr_timer = qp_cmd.get("min_rnr_timer", 0x12)

        response = stub.OpenDevice(
            message_pb2.OpenDeviceRequest(
                dev_name=dev_name,
                access_flag=qp_flag,
                gid_idx=side.gid_idx(),
                ib_port_num=side.ib_port(),
                timeout=timeout,
                retry=retry,
                rnr_retry=rnr_retry,
                mtu=mtu,
                sq_start_psn=sq_start_psn,
                rq_start_psn=rq_start_psn,
                max_rd_atomic=max_rd_atomic,
                max_dest_rd_atomic=max_dest_rd_atomic,
                min_rnr_timer=min_rnr_timer,
            )
        )
        dev_name = response.dev_name
        qp_num = response.qp_num
        lid = response.lid
        gid = response.gid_raw
        cq_id = 0
        pd_id = 0
        qp_id = 0

    logging.info(f"device name is {dev_name}")

    response = stub.CreateMr(
        message_pb2.CreateMrRequest(
            pd_id=pd_id, len=mr_len, flag=mr_flag, dev_name=dev_name
        )
    )
    addr = response.addr
    len = response.len
    rkey = response.rkey
    lkey = response.lkey
    mr_id = response.mr_id

    return (
        SideInfo(
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
        ),
        cmds[1:],
    )
