import logging
import math
import struct

from roce import *
from roce_enum import *
from scapy.all import *


class Util:
    @staticmethod
    def check_pkt_size(mtu, pkt):
        op = pkt[BTH].opcode
        if RC.first_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_FIRST:
            assert len(pkt[Raw].load) == mtu
            assert pkt[BTH].padcount == 0
        elif RC.mid_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_MIDDLE:
            assert len(pkt[Raw].load) == mtu
            assert pkt[BTH].padcount == 0
        elif RC.last_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_LAST:
            assert len(pkt[Raw].load) <= mtu and len(pkt[Raw].load) > 0
        elif RC.only_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_ONLY:
            if pkt.haslayer(Raw):
                assert len(pkt[Raw].load) <= mtu
                assert (
                    len(pkt[Raw].load) % 4 == 0
                ), "payload must be a multiple of a 4 byte packet length"
        return True

    # Check the opcode sequence for received request and response
    @staticmethod
    def check_pre_cur_ops(pre_op, cur_op):
        if pre_op == RC.SEND_FIRST or pre_op == RC.SEND_MIDDLE:
            assert cur_op == RC.SEND_MIDDLE or RC.send_last(cur_op)
        elif pre_op == RC.RDMA_WRITE_FIRST or pre_op == RC.RDMA_WRITE_MIDDLE:
            assert cur_op == RC.RDMA_WRITE_MIDDLE or RC.write_last(cur_op)
        elif (
            pre_op == RC.RDMA_READ_RESPONSE_FIRST
            or pre_op == RC.RDMA_READ_RESPONSE_MIDDLE
        ):
            logging.info(f"pre_op={pre_op}, cur_op={cur_op}")
            # Allow out of order ACK in between read response, or NAK to early terminate read response
            assert (
                cur_op == RC.RDMA_READ_RESPONSE_MIDDLE
                or cur_op == RC.RDMA_READ_RESPONSE_LAST
                or cur_op == RC.ACKNOWLEDGE
            )
        elif (
            RC.last_req_pkt(pre_op)
            or RC.only_req_pkt(pre_op)
            or RC.atomic(pre_op)
            or pre_op == RC.RDMA_READ_RESPONSE_LAST
            or pre_op == RC.RDMA_READ_RESPONSE_ONLY
            or pre_op == RC.ATOMIC_ACKNOWLEDGE
            or pre_op == RC.ACKNOWLEDGE
        ):
            # Expect first/only request or first/only response or ack, not middle/last
            assert not (
                RC.mid_req_pkt(cur_op)
                or RC.last_req_pkt(cur_op)
                or cur_op == RC.RDMA_READ_RESPONSE_MIDDLE
                or cur_op == RC.RDMA_READ_RESPONSE_LAST
            )
        return True

    @staticmethod
    def check_op_with_access_flags(
        rc_op, access_flags
    ):  # Check operation w.r.t. MR or QP flags
        if RC.send(rc_op):
            assert (
                ACCESS_FLAGS.LOCAL_WRITE & access_flags
            ), "send op needs RQ/MR has local write permission"
        elif RC.write(rc_op):
            assert (
                ACCESS_FLAGS.REMOTE_WRITE & access_flags
            ), "write op needs RQ/MR has remote write permission"
        elif rc_op == RC.RDMA_READ_REQUEST:
            assert (
                ACCESS_FLAGS.REMOTE_READ & access_flags
            ), "read op needs RQ/MR has remote read permission"
        elif RC.atomic(rc_op):
            assert (
                ACCESS_FLAGS.REMOTE_ATOMIC & access_flags
            ), "atomic op needs RQ/MR has remote atomic permission"
        elif RC.read_resp(rc_op):
            assert (
                ACCESS_FLAGS.LOCAL_WRITE & access_flags
            ), "read response needs SQ/MR has local write permission"
        elif rc_op == RC.ATOMIC_ACKNOWLEDGE:
            assert (
                ACCESS_FLAGS.LOCAL_WRITE & access_flags
            ), "atomic response needs SQ/MR has local write permission"
        return True

    @staticmethod
    def check_addr_aligned(addr, mr):
        addr_in_mr = addr
        if ACCESS_FLAGS.ZERO_BASED & mr.flags():
            addr_in_mr = mr.addr() + addr
        # # TODO: handle remote access error: length exceeds MR size / Responder Class C
        # assert (
        #     addr_in_mr >= mr.addr()
        #     and addr_in_mr + ATOMIC_BYTE_SIZE <= mr.addr() + mr.len()
        # ), f"address={addr} is not within MR"
        # TODO: handle invalid request error: Misaligned ATOMIC / Responder Class C
        assert addr_in_mr == (
            (addr_in_mr >> 3) << 3
        ), f"address={addr} is not 8-byte aligned"

        return True

    # PSN compare logic:
    # psn_a == psn_b: 0
    # psn_a > psn_b: 1
    # psn_a < psn_b: -1
    @staticmethod
    def psn_compare(psn_a, psn_b, cur_max_psn):
        assert cur_max_psn >= 0 and cur_max_psn < MAX_PSN, "cur_max_psn is invalid"
        assert psn_a >= 0 and psn_a < MAX_PSN, "psn_a is invalid"
        assert psn_b >= 0 and psn_b < MAX_PSN, "psn_b is invalid"

        if psn_a == psn_b:
            return 0
        else:
            oldest_psn = (cur_max_psn - (MAX_PSN / 2)) % MAX_PSN
            if psn_a < psn_b:
                if oldest_psn <= psn_a:
                    return -1
                elif psn_b <= oldest_psn:
                    return -1
                else:
                    return 1
            else:  # psn_a > psn_b
                if oldest_psn >= psn_a:
                    return 1
                elif psn_b >= oldest_psn:
                    return 1
                else:
                    return -1

    @staticmethod
    def raw_data_len(data_pkt):
        if Raw in data_pkt:
            pkt_padcount = data_pkt[BTH].padcount
            return len(data_pkt[Raw].load) - pkt_padcount
        else:
            return 0

    @staticmethod
    def write_to_mr(dst_mr, write_to_mr_addr, data_pkt):
        if Raw in data_pkt:
            data_len = Util.raw_data_len(data_pkt)
            dst_mr.write(data_pkt[Raw].load, addr=write_to_mr_addr, data_len=data_len)
            return data_len
        else:
            return 0

    @staticmethod
    def previous_psn(cur_psn):
        return (cur_psn - 1) % MAX_PSN

    @staticmethod
    def next_psn(cur_psn):
        return (cur_psn + 1) % MAX_PSN

    @staticmethod
    def psn_range(start_psn, end_psn):
        cur_psn = start_psn
        while cur_psn != end_psn:
            yield cur_psn
            cur_psn = Util.next_psn(cur_psn)

    @staticmethod
    def next_ssn(cur_ssn):
        return (cur_ssn + 1) % MAX_SSN

    @staticmethod
    def ssn_range(start_ssn, end_ssn):
        cur_ssn = start_ssn
        while cur_ssn != end_ssn:
            yield cur_ssn
            cur_ssn = Util.next_ssn(cur_ssn)

    @staticmethod
    def compute_wr_pkt_num(wr_size, qp_mtu):
        return math.ceil(wr_size / qp_mtu) if wr_size > 0 else 1

    @staticmethod
    def add_padding_if_needed(pkt):
        pads = [b"", b"\0", b"\0\0", b"\0\0\0"]
        if Raw in pkt:
            raw_data_len = len(pkt[Raw].load)
            padcount = raw_data_len % 4
            if padcount != 0:
                pkt[Raw].load += pads[4 - padcount]
                pkt[BTH].padcount = 4 - padcount
            assert (
                len(pkt[Raw].load) % 4 == 0
            ), "packet payload must be of multipler of 4"
        return pkt

    @staticmethod
    def rnr_timer_to_ns(rnr_timer):
        if rnr_timer == 0:
            timer_ns = 655_360_000
        elif rnr_timer == 1:
            timer_ns = 10_000
        elif rnr_timer == 2:
            timer_ns = 20_000
        elif rnr_timer == 3:
            timer_ns = 30_000
        elif rnr_timer == 4:
            timer_ns = 40_000
        elif rnr_timer == 5:
            timer_ns = 60_000
        elif rnr_timer == 6:
            timer_ns = 80_000
        elif rnr_timer == 7:
            timer_ns = 120_000
        elif rnr_timer == 8:
            timer_ns = 160_000
        elif rnr_timer == 9:
            timer_ns = 240_000
        elif rnr_timer == 10:
            timer_ns = 320_000
        elif rnr_timer == 11:
            timer_ns = 480_000
        elif rnr_timer == 12:
            timer_ns = 640_000
        elif rnr_timer == 13:
            timer_ns = 960_000
        elif rnr_timer == 14:
            timer_ns = 1_280_000
        elif rnr_timer == 15:
            timer_ns = 1_920_000
        elif rnr_timer == 16:
            timer_ns = 2_560_000
        elif rnr_timer == 17:
            timer_ns = 3_840_000
        elif rnr_timer == 18:
            timer_ns = 5_120_000
        elif rnr_timer == 19:
            timer_ns = 7_680_000
        elif rnr_timer == 20:
            timer_ns = 10_240_000
        elif rnr_timer == 21:
            timer_ns = 15_360_000
        elif rnr_timer == 22:
            timer_ns = 20_480_000
        elif rnr_timer == 23:
            timer_ns = 30_720_000
        elif rnr_timer == 24:
            timer_ns = 40_960_000
        elif rnr_timer == 25:
            timer_ns = 61_440_000
        elif rnr_timer == 26:
            timer_ns = 81_920_000
        elif rnr_timer == 27:
            timer_ns = 122_880_000
        elif rnr_timer == 28:
            timer_ns = 163_840_000
        elif rnr_timer == 29:
            timer_ns = 245_760_000
        elif rnr_timer == 30:
            timer_ns = 327_680_000
        elif rnr_timer == 31:
            timer_ns = 491_520_000
        else:
            assert False, f"BUG: unsupported RNR timer value={rnr_timer}"
        return timer_ns

    @staticmethod
    def timeout_to_ns(timeout_val):
        timeout_ns = None
        if timeout_val == 0:
            timeout_ns = -1
        elif timeout_val == 1:
            timeout_ns = 8192
        elif timeout_val == 2:
            timeout_ns == 16_384
        elif timeout_val == 3:
            timeout_ns = 32_768
        elif timeout_val == 4:
            timeout_ns = 65_536
        elif timeout_val == 5:
            timeout_ns = 131_072
        elif timeout_val == 6:
            timeout_ns = 262_144
        elif timeout_val == 7:
            timeout_ns = 524_288
        elif timeout_val == 8:
            timeout_ns = 1_048_576
        elif timeout_val == 9:
            timeout_ns = 2_097_152
        elif timeout_val == 10:
            timeout_ns = 4_196_304
        elif timeout_val == 11:
            timeout_ns = 8_388_608
        elif timeout_val == 12:
            timeout_ns = 16_777_220
        elif timeout_val == 13:
            timeout_ns = 33_554_430
        elif timeout_val == 14:
            timeout_ns = 67_108_860
        elif timeout_val == 15:
            timeout_ns = 134_217_700
        elif timeout_val == 16:
            timeout_ns = 268_435_500
        elif timeout_val == 17:
            timeout_ns = 536_870_900
        elif timeout_val == 18:
            timeout_ns = 1_073_742_000
        elif timeout_val == 19:
            timeout_ns = 2_147_484_000
        elif timeout_val == 20:
            timeout_ns = 4_294_967_000
        elif timeout_val == 21:
            timeout_ns = 8_589_935_000
        elif timeout_val == 22:
            timeout_ns = 17_179_869_000
        elif timeout_val == 23:
            timeout_ns = 34_359_738_000
        elif timeout_val == 24:
            timeout_ns = 68_719_477_000
        elif timeout_val == 25:
            timeout_ns = 137_000_000_000
        elif timeout_val == 26:
            timeout_ns = 275_000_000_000
        elif timeout_val == 27:
            timeout_ns = 550_000_000_000
        elif timeout_val == 28:
            timeout_ns = 1_100_000_000_000
        elif timeout_val == 29:
            timeout_ns = 2_200_000_000_000
        elif timeout_val == 30:
            timeout_ns = 4_400_000_000_000
        elif timeout_val == 31:
            timeout_ns = 8_800_000_000_000
        else:
            assert False, f"BUG: unsupported timeout value={timeout_ns}"
        return timeout_ns


class MR:
    def __init__(self, va, length, access_flags, lkey, rkey):
        self.va = va
        self.local_key = lkey
        self.remote_key = rkey
        self.length = length
        self.access_flags = access_flags
        self.byte_data = bytearray(
            struct.pack(f"<{self.len()}s", b"\0")
        )  # '\0' has no endien issue
        # self.pos = 0

    def addr(self):
        return self.va

    def lkey(self):
        return self.local_key

    def rkey(self):
        return self.remote_key

    def len(self):
        return self.length

    def flags(self):
        return self.access_flags

    def write(self, byte_data, addr=0, data_len=None):
        if data_len is None:
            data_len = len(byte_data)
        addr_in_mr = (
            addr if ACCESS_FLAGS.ZERO_BASED & self.flags() else addr - self.addr()
        )
        assert (
            addr_in_mr >= 0 and addr_in_mr + data_len <= self.len()
        ), "write address and size not within MR"
        self.byte_data[addr_in_mr : (addr_in_mr + data_len)] = byte_data

    def read(self, addr, size):
        addr_in_mr = (
            addr if ACCESS_FLAGS.ZERO_BASED & self.flags() else addr - self.addr()
        )
        assert (
            addr_in_mr >= 0 and addr_in_mr + size <= self.len()
        ), "read address and size not within MR"
        return self.byte_data[addr_in_mr : (addr_in_mr + size)]


class PD:
    def __init__(self, pdn):
        self.pdn = pdn
        self.qp_dict = {}
        self.mr_dict = {}
        self.next_key = 1

    def reg_mr(self, va, length, access_flags):
        mr = MR(
            va=va,
            length=length,
            access_flags=access_flags,
            lkey=self.next_key,
            rkey=self.next_key,
        )
        self.mr_dict[mr.lkey()] = mr
        self.mr_dict[mr.rkey()] = mr
        self.next_key += 1
        return mr

    def dereg_mr(self, mr):
        del self.mr_dict[mr.rkey()]
        if mr.lkey() in self.mr_dict:
            del self.mr_dict[mr.lkey()]

    def has_mr(self, lrkey):
        return lrkey in self.mr_dict

    def get_mr(self, lrkey):
        return self.mr_dict[lrkey]

    def add_qp(self, qp):
        self.qp_dict[qp.qpn()] = qp

    def check_mr_access(self, rc_op, lrkey):
        if not self.has_mr(lrkey):
            logging.error("invalid lkey or rkey")
            return None
        mr = self.get_mr(lrkey)
        if Util.check_op_with_access_flags(rc_op, mr.flags()):
            return mr
        else:
            logging.error("no enough permission for the operation")
            return None

    def check_mr_size(self, lrkey, addr, data_size):
        mr = self.get_mr(lrkey)
        addr_in_mr = addr
        if ACCESS_FLAGS.ZERO_BASED & mr.flags():
            addr_in_mr = mr.addr() + addr
        if addr_in_mr >= mr.addr() and addr_in_mr + data_size <= mr.addr() + mr.len():
            return True
        else:
            logging.error("address or length not within MR")
            return False


class CQE:
    def __init__(
        self,
        wr_id,
        status,
        opcode,
        length,
        qpn,
        src_qp,
        wc_flags,
        imm_data_or_inv_rkey=None,
    ):
        self.wr_id = wr_id
        self.cqe_status = status
        self.opcode = opcode
        self.length = length
        self.qpn = qpn
        self.src_qp = src_qp
        self.wc_flags = wc_flags
        self.imm_data_inv_rkey = imm_data_or_inv_rkey

    def id(self):
        return self.wr_id

    def op(self):
        return self.opcode

    def len(self):
        return self.length

    def local_qpn(self):  # local QPN
        return self.qpn

    def sqpn(self):
        return self.src_qp

    def status(self):
        return self.cqe_status

    def imm_data_or_inv_rkey(self):
        return self.imm_data_inv_rkey


class CQ:
    def __init__(self, cqn):
        self.cqn = cqn
        self.cq = []

    def pop(self):
        return self.cq.pop(0)

    def push(self, cqe):
        self.cq.append(cqe)

    def empty(self):
        return not bool(self.cq)

    def clear(self):
        self.cq.clear()
