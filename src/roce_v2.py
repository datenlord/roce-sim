import copy
import logging
import random
import socket
import struct
import sys

# from logging import debug, info, warning, error, critical
from roce_enum import *
from scapy.all import *
from roce import *

ATOMIC_BYTE_SIZE = 8
UDP_BUF_SIZE = 1024

CREDIT_CNT_INVALID = 31
DEFAULT_PKEY = 0xFFFF
DEFAULT_RNR_WAIT_TIME = 4
DEFAULT_TIMEOUT = 4
EMPTY_SEND_FLAG = 0
EMPTY_WC_FLAG = 0
ROCE_PORT = 4791
RSRV_AETH_NAK_VAL = 31

MAX_SSN = 2**24
MAX_MSN = 2**24
MAX_PSN = 2**24

class Util:
    def check_pkt_size(mtu, pkt):
        op = pkt[BTH].opcode
        if RC.first_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_FIRST:
            assert len(pkt[Raw].load) == mtu
        elif RC.mid_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_MIDDLE:
            assert len(pkt[Raw].load) == mtu
        elif RC.last_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_LAST:
            assert len(pkt[Raw].load) <= mtu and len(pkt[Raw].load) > 0
        elif RC.only_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_ONLY:
            if pkt.haslayer(Raw):
                assert len(pkt[Raw].load) <= mtu
                assert len(pkt[Raw].load) % 4 == 0, 'payload must be a multiple of a 4 byte packet length'
        return True

    def check_pre_cur_ops(pre_op, cur_op):
        # TODO: handle invalid request error: Out of Sequence OpCode / Responder Class C
        if pre_op == RC.SEND_FIRST or pre_op == RC.SEND_MIDDLE:
            assert cur_op == RC.SEND_MIDDLE or RC.send_last(cur_op)
        elif pre_op == RC.RDMA_WRITE_FIRST or pre_op == RC.RDMA_WRITE_MIDDLE:
            assert cur_op == RC.RDMA_WRITE_MIDDLE or RC.write_last(cur_op)
        elif pre_op == RC.RDMA_READ_RESPONSE_FIRST or pre_op == RC.RDMA_READ_RESPONSE_MIDDLE:
            # Allow out of order ACK in between read response, or NAK to early terminate read response
            assert cur_op == RC.RDMA_READ_RESPONSE_MIDDLE or cur_op == RC.RDMA_READ_RESPONSE_LAST or cur_op == RC.ACKNOWLEDGE
        elif (RC.last_req_pkt(pre_op) or RC.only_req_pkt(pre_op) or RC.atomic(pre_op)
                or pre_op == RC.RDMA_READ_RESPONSE_LAST or pre_op == RC.RDMA_READ_RESPONSE_ONLY
                or pre_op == RC.ATOMIC_ACKNOWLEDGE or pre_op == RC.ACKNOWLEDGE):
            # Expect first/only request or first/only response or ack, not middle/last
            assert not (RC.mid_req_pkt(cur_op) or RC.last_req_pkt(cur_op)
                        or cur_op == RC.RDMA_READ_RESPONSE_MIDDLE or cur_op == RC.RDMA_READ_RESPONSE_LAST)
        return True

    def check_op_with_access_flags(rc_op, access_flags): # Check operation w.r.t. MR or QP flags
        if RC.send(rc_op):
            assert ACCESS_FLAGS.LOCAL_WRITE & access_flags, 'send op needs RQ/MR has local write permission'
        elif RC.write(rc_op):
            assert ACCESS_FLAGS.REMOTE_WRITE & access_flags, 'write op needs RQ/MR has remote write permission'
        elif rc_op == RC.RDMA_READ_REQUEST:
            assert ACCESS_FLAGS.REMOTE_READ & access_flags, 'read op needs RQ/MR has remote read permission'
        elif RC.atomic(rc_op):
            assert ACCESS_FLAGS.REMOTE_ATOMIC & access_flags, 'atomic op needs RQ/MR has remote atomic permission'
        elif RC.read_resp(rc_op):
            assert ACCESS_FLAGS.LOCAL_WRITE & access_flags, 'read response needs SQ/MR has local write permission'
        elif rc_op == RC.ATOMIC_ACKNOWLEDGE:
            assert ACCESS_FLAGS.LOCAL_WRITE & access_flags, 'atomic response needs SQ/MR has local write permission'
        return True

    def check_addr_aligned(addr, mr):
        addr_in_mr = addr
        if ACCESS_FLAGS.ZERO_BASED & mr.flags():
            addr_in_mr = mr.addr() + addr
        # TODO: handle remote access error: length exceeds MR size / Responder Class C
        assert addr_in_mr >= mr.addr() and addr_in_mr + ATOMIC_BYTE_SIZE <= mr.addr() + mr.len(), f'address={addr} is not within MR'
        # TODO: handle invalid request error: Misaligned ATOMIC / Responder Class C
        assert addr_in_mr == ((addr_in_mr >> 3) << 3)

        return True

    # PSN compare logic:
    # psn_a == psn_b: 0
    # psn_a > psn_b: 1
    # psn_a < psn_b: -1
    def psn_compare(psn_a, psn_b, cur_max_psn):
        assert cur_max_psn >= 0 and cur_max_psn < MAX_PSN, 'cur_max_psn is invalid'
        assert psn_a >= 0 and psn_a < MAX_PSN, 'psn_a is invalid'
        assert psn_b >= 0 and psn_b < MAX_PSN, 'psn_b is invalid'

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
            else: # psn_a > psn_b
                if oldest_psn >= psn_a:
                    return 1
                elif psn_b >= oldest_psn:
                    return 1
                else:
                    return -1

    def write_to_mr(dst_mr, write_to_mr_addr, data_pkt):
        if Raw in data_pkt:
            pkt_padcount = data_pkt[BTH].padcount
            data_len = len(data_pkt[Raw].load) - pkt_padcount
            dst_mr.write(data_pkt[Raw].load, addr = write_to_mr_addr, data_len = data_len)
            return data_len
        else:
            return 0

    def previous_psn(cur_psn):
        return (cur_psn - 1) % MAX_PSN

    def next_psn(cur_psn):
        return (cur_psn + 1) % MAX_PSN

    def psn_range(start_psn, end_psn):
        cur_psn = start_psn
        while cur_psn != end_psn:
            yield cur_psn
            cur_psn = Util.next_psn(cur_psn)

    def compute_wr_pkt_num(wr_size, qp_mtu):
        return math.ceil(wr_size / qp_mtu) if wr_size > 0 else 1

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
            raise Exception(f'unsupported RNR timer value={rnr_timer}')
        return timer_ns

    def timeout_to_ns(timeout_val):
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
            raise Exception(f'unsupported timeout value={timeout_ns}')
        return timeout_ns

class MR:
    def __init__(self, va, length, access_flags, lkey, rkey):
        self.va = va
        self.local_key = lkey
        self.remote_key = rkey
        self.length = length
        self.access_flags = access_flags
        self.byte_data = bytearray(struct.pack(f'<{self.len()}s', b'\0')) # '\0' has no endien issue
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

    def write(self, byte_data, addr = 0, data_len = None):
        if data_len is None:
            data_len = len(byte_data)
        addr_in_mr = addr if ACCESS_FLAGS.ZERO_BASED & self.flags() else addr - self.addr()
        assert addr_in_mr >= 0 and addr_in_mr + data_len <= self.len(), 'write address and size not within MR'
        self.byte_data[addr_in_mr : (addr_in_mr + data_len)] = byte_data

    def read(self, addr, size):
        addr_in_mr = addr if ACCESS_FLAGS.ZERO_BASED & self.flags() else addr - self.addr()
        assert addr_in_mr >= 0 and addr_in_mr + size <= self.len(), 'read address and size not within MR'
        return self.byte_data[addr_in_mr: (addr_in_mr + size)]

class PD:
    def __init__(self, pdn):
        self.pdn = pdn
        self.qp_dict = {}
        self.mr_dict = {}
        self.next_key = 1
    
    def reg_mr(self, va, length, access_flags):
        mr = MR(va = va, length = length, access_flags = access_flags, lkey = self.next_key, rkey = self.next_key)
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

    def validate_mr(self, rc_op, lrkey, addr, data_size):
        assert self.has_mr(lrkey), 'invalid lkey or rkey'
        mr = self.get_mr(lrkey)
        addr_in_mr = addr
        if ACCESS_FLAGS.ZERO_BASED & mr.flags():
            addr_in_mr = mr.addr() + addr

        # TODO: handle invalid request error: Length error / Responder Class C
        assert addr_in_mr >= mr.addr() and addr_in_mr + data_size <= mr.addr() + mr.len(), 'address or length not within MR'
        # TODO: handle remote access error: R_Key Violation / Responder Class C
        assert Util.check_op_with_access_flags(rc_op, mr.flags()), 'no enough permission for the operation'

        return True

class CQE:
    def __init__(self, wr_id, status, opcode, length, qpn, src_qp, wc_flags, imm_data_or_inv_rkey = None):
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
        
    def local_qpn(self): # local QPN
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

# class SGE:
#     def __init__(self, addr, length, lkey, data = b''):
#         self.addr = addr
#         self.length = length
#         self.lkey = lkey
#         self.byte_data = data
    
#     def data(self):
#         return self.byte_data

#     def len(self):
#         return self.length

#     def write(self, byte_data):
#         self.byte_data = byte_data

#     def read(self):
#         return self.byte_data

#     def append(self, byte_data):
#         self.byte_data += byte_data

# class SGL:
#     def __init__(self):
#         self.sg_list = []
#         self.length = 0
#         self.byte_data = b''
    
#     def append(self, sge):
#         self.sg_list.append(sge)
#         self.length += sge.len()
#         self.byte_data += sge.data() # TODO: do not copy data

#     def data(self):
#         return self.byte_data

#     def len(self):
#         return self.length

class SG:
    def __init__(self, pos_in_mr, length, lkey):
        self.pos_in_mr = pos_in_mr
        self.length = length
        self.local_key = lkey

    def addr(self):
        return self.pos_in_mr

    def len(self):
        return self.length

    def lkey(self):
        return self.local_key

class SendWR:
    def __init__(self, opcode, sgl,
        wr_id = None,
        send_flags = EMPTY_SEND_FLAG,
        rmt_va = None,
        rkey = None,
        compare_add = None,
        swap = None,
        imm_data_or_inv_rkey = None,
    ):
        self.opcode = opcode
        self.send_flags = send_flags
        self.sgl = sgl
        self.wr_id = wr_id
        self.rmt_va = rmt_va
        self.remote_key = rkey
        self.compare_add_data = compare_add
        self.swap_data = swap
        self.imm_data_inv_rkey = imm_data_or_inv_rkey

    def id(self):
        return self.wr_id

    def len(self):
        return self.sgl.len()

    def op(self):
        return self.opcode

    def lkey(self):
        # TODO: handle the case of sgl is None
        return self.sgl.lkey()

    def rkey(self):
        return self.remote_key

    def laddr(self):
        return self.sgl.addr()

    def raddr(self):
        return self.rmt_va

    def flags(self):
        return self.send_flags

    def imm_data_or_inv_rkey(self):
        return self.imm_data_inv_rkey

    def comp(self):
        return self.compare_add_data

    def swap(self):
        return self.swap_data

class RecvWR:
    def __init__(self, sgl, wr_id = 0):
        self.sgl = sgl
        self.wr_id = wr_id

    def id(self):
        return self.wr_id

    def lkey(self):
        return self.sgl.lkey()

    def addr(self):
        return self.sgl.addr()

class WRContext:
    def __init__(self, wr):
        self.wr = wr
        self.wr_req_dict = {}
        self.first_pkt_psn = None

    def other_retry_inc(self, pkt_psn, other_retry_limit):
        assert pkt_psn in self.wr_req_dict, 'other_retry_inc() error: the PSN is not for packets of this WR'
        (rnr_retry_cnt, retry_cnt) = self.wr_req_dict[pkt_psn]
        if retry_cnt >= other_retry_limit:
            return False
        self.wr_req_dict[pkt_psn] = (rnr_retry_cnt, retry_cnt + 1)
        return True

    def rnr_retry_inc(self, pkt_psn, rnr_retry_limit):
        assert pkt_psn in self.wr_req_dict, 'rnr_retry_inc() error: the PSN is not for packets of this WR'
        (rnr_retry_cnt, retry_cnt) = self.wr_req_dict[pkt_psn]
        if rnr_retry_cnt >= rnr_retry_limit:
            return False
        self.wr_req_dict[pkt_psn] = (rnr_retry_cnt + 1, retry_cnt)
        return True

    def retry_num(self, pkt_psn):
        assert pkt_psn in self.wr_req_dict, 'retry_num() error: the PSN is not for packets of this WR'
        (rnr_retry_cnt, retry_cnt) = self.wr_req_dict[pkt_psn]
        return retry_cnt

    def rnr_retry_num(self, pkt_psn):
        assert pkt_psn in self.wr_req_dict, 'rnr_retry_num() error: the PSN is not for packets of this WR'
        (rnr_retry_cnt, retry_cnt) = self.wr_req_dict[pkt_psn]
        return rnr_retry_cnt

    def add_pkt(self, pkt):
        pkt_psn = pkt[BTH].psn
        if self.first_pkt_psn is None:
            self.first_pkt_psn = pkt_psn
        retry_cnt = 0
        rnr_retry_cnt = 0
        self.wr_req_dict[pkt_psn] = (rnr_retry_cnt, retry_cnt)

    def pkt_num(self):
        return len(self.wr_req_dict)

    def first_psn(self):
        return self.first_pkt_psn

class SendOutstandingContext:
    def __init__(self, qp):
        self.qp = qp
        self.min_unacked_psn = qp.sq.sq_psn
        self.dst_ip = None

        self.pending_wr_dict = {} # The WR SSN -> (WR, dict(req_pkt_psn -> retry_num))
        self.req_pkt_psn_wr_ssn_dict = {} # The request packet PSN -> WR SSN
        self.read_resp_psn_wr_ssn_dict = {} # The read response packet PSN -> (read WR SSN, read request PSN)
        self.pending_read_ctx_dict = {} # The read request SSN -> (read_offset, dict(read_resp_psn -> ))

        self.oldest_sent_ts_ns = None # Keep track of the oldest sent packet
        self.pending_rd_atomic_wr_num = 0

    def modify(self, sq_psn = None):
        if sq_psn is not None:
            self.min_unacked_psn = sq_psn
        self.set_dst_ip()

    def set_dst_ip(self):
        # ip_hex = socket.inet_aton('192.168.122.190').hex()
        # dst_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(self.dgid))
        dst_ipv6 = socket.inet_ntop(socket.AF_INET6, self.qp.dgid())
        dst_ipv4 = dst_ipv6.replace('::ffff:', '')
        self.dst_ip = dst_ipv6 if self.qp.use_ipv6 else dst_ipv4

    def cq(self):
        return self.qp.sq.cq

    def npsn(self): # Next SQ PSN
        return self.qp.sq.sq_psn

    def epsn(self): # Expected RQ PSN
        return self.qp.rq.rq_psn

    def mpsn(self): # Min unacked SQ PSN
        return self.min_unacked_psn

    def sqpn(self): # Source QPN
        return self.qp.qpn()

    def dqpn(self): # Destination QPN
        return self.qp.dqpn()

    def full(self):
        return self.pending_rd_atomic_wr_num >= self.qp.max_dest_rd_atomic

    def empty(self):
        if not self.pending_wr_dict:
            assert not self.req_pkt_psn_wr_ssn_dict, 'req_pkt_psn_wr_ssn_dict should be empty'
            assert not self.read_resp_psn_wr_ssn_dict, 'read_resp_psn_wr_ssn_dict should be empty'
            assert not self.pending_read_ctx_dict, 'pending_read_ctx_dict should be empty'
        return not self.pending_wr_dict

    def flush(self):
        for pending_ssn, wr_ctx in self.pending_wr_dict.items():
            pending_sr = wr_ctx.wr
            rc_op = unacked_pkt[BTH].opcode
            flush_pending_cqe = CQE(
                wr_id = pending_sr.id(),
                status = WC_STATUS.WR_FLUSH_ERR,
                opcode = WC_OPCODE.from_wr_op(pending_sr.id()),
                length = nak_sr.len(),
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = EMPTY_WC_FLAG,
            )
            self.cq.push(flush_pending_cqe)
            #self.delete_wr(pending_ssn) BUG: cannot iterate a dictory and remove from it

        # Clear all pending WR, packets
        self.pending_wr_dict.clear() # Delete all pending WR
        self.req_pkt_psn_wr_ssn_dict.clear() # Delete all pending request data
        self.read_resp_psn_wr_ssn_dict.clear() # Delete all pending read response data
        self.pending_read_ctx_dict.clear() # Delete all pending read response context data

    def add_wr(self, wr, wr_ssn):
        self.pending_wr_dict[wr_ssn] = WRContext(wr)

        read_or_atomic = WR_OPCODE.RDMA_READ == wr.opcode or WR_OPCODE.atomic(wr.op())
        if read_or_atomic:
            self.pending_rd_atomic_wr_num += 1
        if read_or_atomic or (SEND_FLAGS.SIGNALED & wr.flags()):
            self.update_oldest_sent_ts(ack_or_timeout = False) # Update oldest_sent_ts if is None

    def add_pkt(self, wr_ssn, pkt):
        pkt_psn = pkt[BTH].psn
        wr_ctx = self.pending_wr_dict[wr_ssn]
        self.req_pkt_psn_wr_ssn_dict[pkt_psn] = (wr_ssn, pkt)
        wr_ctx.add_pkt(pkt)

    # oldest_sent_ts_ns is updated in 3 cases:
    # - ACK or NAK received
    # - timeout detected and retry
    # - oldest_sent_ts_ns is None and there's new packet to send
    def update_oldest_sent_ts(self, ack_or_timeout = False): # TODO: change ack_or_timeout to Enum
        if ack_or_timeout or self.oldest_sent_ts_ns is None:
            if not self.empty(): # There are unacked requests
                self.oldest_sent_ts_ns = time.time_ns()
            else:
                self.oldest_sent_ts_ns = None # No outstanding request

    # min_unacked_psn is updated in 2 cases:
    # - explicit ACK received
    # - implicit ACK
    def update_min_unacked_psn(self, min_unacked_psn): # TODO: delete acked request packets
        if self.min_unacked_psn != min_unacked_psn:
            self.min_unacked_psn = min_unacked_psn

    def is_expected_resp(self, resp_psn):
        if self.mpsn() == self.npsn():
            # No response expected
            return False
        else:
            assert Util.psn_compare(
                self.mpsn(),
                self.npsn(),
                self.npsn(),
            ) < 0, 'min unacked PSN not < SQ PSN'
            if (Util.psn_compare(self.mpsn(), resp_psn, self.npsn()) <= 0
                and Util.psn_compare(self.npsn(), resp_psn, self.npsn()) > 0):
                return True
            else:
                # Either dup or illegal response
                return False

    def handle_dup_or_illegal_resp(self, resp):
        if self.mpsn() == self.npsn(): # No response expected
            logging.info(f'SQ={self.sqpn()} received ghost response: ' + resp.show(dump = True))
        else: # SQ discard duplicate or illegal response, except for unsolicited flow control credit
            psn_comp_res = Util.psn_compare(resp[BTH].psn, self.mpsn(), self.npsn())
            assert psn_comp_res != 0, 'should handle duplicate or illegal response'
            if psn_comp_res < 0: # Dup resp
                logging.debug(f'SQ={self.sqpn()} received duplicate response: ' + resp.show(dump = True))
                nxt_psn = Util.next_psn(resp[BTH].psn)
                if nxt_psn == self.mpsn(): # Unsolicited flow control credit
                    assert AETH in resp, 'unsolicited flow control credit ACK should have AETH'
                    assert resp[AETH].code == 0, 'unsolicited flow control credit ACK code should be 0'
                    credit_cnt = resp[AETH].value
                    logging.debug(f'SQ={self.sqpn()} received unsolicited flow control credit={credit_cnt}')
            else: # Illegal response, just discard
                assert Util.psn_compare(
                    self.npsn(),
                    resp[BTH].psn,
                    self.npsn(),
                ) <= 0, 'should handle illegal response'
                logging.debug(f'SQ={self.sqpn()} received illegal response: ' + resp.show(dump = True))

    # There are 4 case to delete outstanding WQE:
    # - ACK received, delete finished send or write WR
    # - unrecoverable NAK received, delete NAK related WR
    # - read response received, delete finished read WR
    # - atomic response received, delete finished atomic WR
    def delete_wr(self, ssn_to_delete):
        wr_ctx = self.pending_wr_dict[ssn_to_delete]
        wr_to_delete = wr_ctx.wr
        wr_req_dict = wr_ctx.wr_req_dict
        wr_op = wr_to_delete.op()
        if wr_op == WR_OPCODE.RDMA_READ or WR_OPCODE.atomic(wr_op):
            self.pending_rd_atomic_wr_num -= 1
            assert self.pending_rd_atomic_wr_num >= 0, 'pending_rd_atomic_wr_num should not < 0'
        if wr_op == WR_OPCODE.RDMA_READ: # Clean up read response context
            read_offset, resp_pkt_psn_dict = self.pending_read_ctx_dict[ssn_to_delete]
            # Cleanup finished read response PSN
            for resp_pkt_psn in resp_pkt_psn_dict.keys():
                del self.read_resp_psn_wr_ssn_dict[resp_pkt_psn]
            resp_pkt_psn_dict.clear()
            del self.pending_read_ctx_dict[ssn_to_delete]
        # Clean up finished request PSN
        for req_pkt_psn in wr_req_dict.keys():
            del self.req_pkt_psn_wr_ssn_dict[req_pkt_psn]
        wr_req_dict.clear()
        del self.pending_wr_dict[ssn_to_delete]

    def get_pending_wr(self, pending_wr_ssn):
        pending_wr_ctx = self.pending_wr_dict[pending_wr_ssn]
        return pending_wr_ctx.wr

    def do_send_pkt(self, pkt):
        l3_pkt = IP(dst=self.dst_ip)/UDP(dport=ROCE_PORT, sport=self.sqpn())/pkt
        logging.debug(f'SQ={self.sqpn()} sent to IP={self.dst_ip} a request: ' + l3_pkt.show(dump = True))
        send(l3_pkt)
        return WC_STATUS.SUCCESS

    def send_req_pkt(self, wr_ssn, req_pkt):
        assert wr_ssn in self.pending_wr_dict, 'before send_req_pkt(), it should add its WR to pending_wr_dict first'
        req_pkt_psn = req_pkt[BTH].psn
        rc_op = req_pkt[BTH].psn
        self.add_pkt(wr_ssn, req_pkt)

        return self.do_send_pkt(req_pkt)

    def send_read_req_pkt(self, read_wr_ssn, read_req_pkt, read_resp_pkt_num):
        read_req_psn = read_req_pkt[BTH].psn
        read_size = read_req_pkt[BTH].dlen
        # Save each read response PSN to read WR SSN mapping
        resp_pkt_psn_dict = {}
        resp_raddr = read_req_pkt[RETH].va
        remaining_dlen = read_size
        remaining_resp_pkt_num = read_resp_pkt_num
        for read_resp_pkt_psn in Util.psn_range(read_req_psn, (read_req_psn + read_resp_pkt_num) % MAX_PSN):
            self.read_resp_psn_wr_ssn_dict[read_resp_pkt_psn] = (read_wr_ssn, read_req_psn)
            resp_pkt_psn_dict[read_resp_pkt_psn] = (resp_raddr, remaining_dlen, remaining_resp_pkt_num)
            resp_raddr += self.qp.mtu()
            remaining_dlen -= self.qp.mtu()
            remaining_resp_pkt_num -= 1
        assert remaining_resp_pkt_num == 0, 'remaining_resp_pkt_num should == 0'
        # Prepare read response context
        read_offset = 0
        self.pending_read_ctx_dict[read_wr_ssn] = (read_offset, resp_pkt_psn_dict)

        return self.send_req_pkt(read_wr_ssn, read_req_pkt)

    def send_retry_pkt(self, wr_ssn, req_pkt, retry_type, partial_read_retry = False):
        req_pkt_psn = req_pkt[BTH].psn
        rc_op = req_pkt[BTH].psn
        wr_ctx = self.pending_wr_dict[wr_ssn]
        # if retry_type != RETRY_TYPE.NONE:
        if partial_read_retry:
            # For partial read retry, it'll generate a read request with different PSN as the origianl read request
            self.add_pkt(wr_ssn, req_pkt)
        if retry_type == RETRY_TYPE.RNR:
            inc_res = wr_ctx.rnr_retry_inc(req_pkt_psn, self.qp.rnr_retry)
            if not inc_res: # RNR retry limit exceeded
                return WC_STATUS.RNR_RETRY_EXC_ERR
        elif RETRY_TYPE.non_rnr_retry(retry_type):
            inc_res = wr_ctx.other_retry_inc(req_pkt_psn, self.qp.retry_cnt)
            if not inc_res: # Retry limit exceeded
                return WC_STATUS.RETRY_EXC_ERR
        else:
            raise Exception(f'unsupported retry type: {retry_type}')

        return self.do_send_pkt(req_pkt)

    def handle_expected_resp(self, resp, retry_handler = None):
        rc_op = resp[BTH].opcode
        resp_psn = resp[BTH].psn
        assert resp[BTH].dqpn == self.qp.qpn(), 'QPN not match with ACK packet'
        assert self.is_expected_resp(resp_psn), 'should expect valid response, not duplicate or illegal one'
        col_ack_res, psn_begin_retry, implicit_ack_pkt_num = self.coalesce_ack(resp_psn)

        handle_res = None
        err_psn = None
        if not col_ack_res: # There are read or atomic requests being implicit NAK, should retry
            logging.info(f'SQ={self.sqpn()} has implicit ACK-ed packtes, needs to retry from PSN={psn_begin_retry}')
            assert self.mpsn() == psn_begin_retry, 'coalesce_ack() should have update min_unacked_psn to psn_begin_retry'
            if rc_op == RC.ACKNOWLEDGE:
                assert resp[AETH].code == 0, 'only ACK can have implicit NAK, NAK cannot be nested'
            handle_res, err_psn = self.retry_pkts(
                psn_begin_retry = psn_begin_retry,
                retry_type = RETRY_TYPE.IMPLICIT,
                retry_handler = retry_handler,
            )
        else:
            if RC.read_resp(rc_op):
                handle_res, err_psn = self.handle_read_resp(resp)
            elif rc_op == RC.ATOMIC_ACKNOWLEDGE:
                handle_res, err_psn = self.handle_atomic_ack(resp)
            elif rc_op == RC.ACKNOWLEDGE:
                handle_res, err_psn = self.handle_ack(resp, retry_handler)
            else:
                handle_res = WC_STATUS.BAD_RESP_ERR
                err_psn = ack[BTH].psn
                logging.error(f'unsupported response opcode={rc_op}')

            if AETH in resp and resp[AETH].code == 0: # ACK received, update min_unacked_psn
                self.update_min_unacked_psn(Util.next_psn(resp_psn))

        if handle_res != WC_STATUS.SUCCESS:
            self.goto_err_state(err_psn, handle_res) # QP error state

        self.update_oldest_sent_ts(ack_or_timeout = True) # Update oldest_sent_ts when ACK or NAK received
        logging.debug(f'min unacked PSN={self.mpsn()}, next PSN={self.npsn()}, implicit_ack_pkt_num={implicit_ack_pkt_num}, pending_rd_atomic_wr_num={self.pending_rd_atomic_wr_num}')

    def check_timeout_and_retry(self):
        if self.oldest_sent_ts_ns is not None:
            cur_ts_ns = time.time_ns()
            timeout_ns = Util.timeout_to_ns(self.qp.timeout)
            if self.oldest_sent_ts_ns + timeout_ns < cur_ts_ns:
                assert Util.psn_compare(
                    self.mpsn(),
                    self.npsn(),
                    self.npsn(),
                ) < 0, 'when timeout there should have outstanding requests'
                logging.info(f'SQ={self.sqpn()} detected timeout and retry from PSN={self.mpsn()} to PSN={self.npsn()} (not included)')
                retry_res, err_pkt_psn = self.retry_one_wr_by_psn(
                    psn_begin_retry = self.mpsn(),
                    retry_type = RETRY_TYPE.TIMEOUT,
                ) # Only retry oldest WR
                if retry_res != WC_STATUS.SUCCESS:
                    return (retry_res, err_pkt_psn)
                self.update_oldest_sent_ts(ack_or_timeout = True) # Update oldest_sent_ts when timeout retry
        return (WC_STATUS.SUCCESS, Util.next_psn(self.mpsn()))

    # There are 2 cases to retry one WR:
    # - timeout retry the oldest unacked request
    # - RNR NAK retry the specified request # TODO: need to confirm
    # This function might not retry the whole WR, specified by psn_begin_retry
    def retry_one_wr_by_psn(self, psn_begin_retry, retry_type, retry_handler = None):
        ssn_to_retry, _ = self.req_pkt_psn_wr_ssn_dict[psn_begin_retry]
        wr_ctx = self.pending_wr_dict[ssn_to_retry]
        psn_end_retry = (wr_ctx.first_psn() + wr_ctx.pkt_num()) % MAX_PSN
        if psn_begin_retry is None:
            psn_begin_retry = wr_ctx.first_psn()
        else:
            assert Util.psn_compare(
                wr_ctx.first_psn(),
                psn_begin_retry,
                self.npsn(),
            ) <= 0, 'wr_ctx.first_psn() should <= retry_from_psn'
            assert Util.psn_compare(
                psn_begin_retry,
                psn_end_retry,
                self.npsn(),
            ) <= 0, 'retry_from_psn should <= retry_end_psn'
        return self.retry_pkts(
            psn_begin_retry = psn_begin_retry,
            psn_end_retry = psn_end_retry,
            retry_type = retry_type,
            retry_handler = retry_handler,
        )

    # There are 2 cases to retry multiple packets:
    # - NAK sequence error received, retry all request packets after the specified PSN
    # - implicit NAK, retry all request packets after the implicit NAK PSN
    def retry_pkts(self, psn_begin_retry, retry_type, psn_end_retry = None, retry_handler = None):
        if psn_end_retry is None:
            # Retry packet with PSN from psn_begin_retry to psn_end_retry (not included)
            psn_end_retry = self.npsn()

        if retry_handler:
            retry_handler()

        #retry_wr_ctx = None
        if psn_begin_retry not in self.req_pkt_psn_wr_ssn_dict: # psn_begin_retry is a partial read response PSN
            # Update psn_begin_retry to next WR PSN, if error occured, psn_begin_retry is the original read request PSN
            partial_retry_res, psn_begin_retry = self.retry_partial_read(
                partial_read_resp_psn = psn_begin_retry,
                retry_type = retry_type,
            )
            if partial_retry_res != WC_STATUS.SUCCESS:
                return (retry_send_res, psn_begin_retry)

        for retry_psn in Util.psn_range(psn_begin_retry, psn_end_retry):
            if retry_psn != psn_end_retry:
                if retry_psn in self.req_pkt_psn_wr_ssn_dict:
                    retry_wr_ssn, pkt_to_retry = self.req_pkt_psn_wr_ssn_dict[retry_psn]
                    retry_send_res = self.send_retry_pkt(retry_wr_ssn, pkt_to_retry, retry_type = retry_type)
                    assert retry_send_res in [
                        WC_STATUS.SUCCESS,
                        WC_STATUS.RETRY_EXC_ERR,
                        WC_STATUS.RNR_RETRY_EXC_ERR,
                    ], 'send_retry_pkt() returned wrong result in retry_pkts()'
                    if retry_send_res != WC_STATUS.SUCCESS:
                        return (retry_send_res, retry_psn)
                else:
                    assert retry_psn in self.read_resp_psn_wr_ssn_dict, 'incorrect PSN, it should either in req_pkt_psn_wr_ssn_dict or read_resp_psn_wr_ssn_dict'
        return (WC_STATUS.SUCCESS, psn_end_retry)

    # As for read request, since it might have multiple response packets, in case of retry,
    # the retry might start from the middle of read response, this is partial retry for read request.
    # As for send/write request, partial retry is not a problem.
    # As for atomic request, no partial retry issue.
    def retry_partial_read(self, partial_read_resp_psn, retry_type):
        assert partial_read_resp_psn not in self.req_pkt_psn_wr_ssn_dict, 'partial_read_resp_psn should be a mid or last read request PSN and not in req_pkt_psn_wr_ssn_dict'
        assert partial_read_resp_psn in self.read_resp_psn_wr_ssn_dict, 'incorrect NAK sequence error PSN to retry, it should be in read_resp_psn_wr_ssn_dict'
        retry_read_wr_ssn, orig_read_req_psn = self.read_resp_psn_wr_ssn_dict[partial_read_resp_psn]
        orig_read_wr_ssn, orig_read_req = self.req_pkt_psn_wr_ssn_dict[orig_read_req_psn]
        assert orig_read_wr_ssn == orig_read_wr_ssn, 'orig_read_wr_ssn shoud == orig_read_wr_ssn'

        # Build a new read request, but its PSN is within the range of the read response to the original read request
        retry_read_req = copy.deepcopy(orig_read_req)
        read_offset, resp_pkt_psn_dict = self.pending_read_ctx_dict[retry_read_wr_ssn]
        retry_read_req[BTH].psn = partial_read_resp_psn
        (
            retry_read_req[RETH].va,
            retry_read_req[RETH].dlen,
            remaining_read_resp_pkt_num,
        ) = resp_pkt_psn_dict[partial_read_resp_psn]

        assert retry_read_req[RETH].dlen != 0, 'retry read request DMA length should not be zero, otherwise no need to retry'
        retry_send_res = self.send_retry_pkt(orig_read_wr_ssn, retry_read_req, retry_type = retry_type, partial_read_retry = True)
        assert retry_send_res in [
            WC_STATUS.SUCCESS,
            WC_STATUS.RETRY_EXC_ERR,
            WC_STATUS.RNR_RETRY_EXC_ERR,
        ], 'send_pkt() returned wrong result in retry_partial_read()'
        if retry_send_res != WC_STATUS.SUCCESS:
            return (retry_send_res, orig_read_req_psn) # If retry error, return orig_read_req_psn

        logging.debug(f'original read request of PSN={orig_read_req_psn} is retried, the retried read request PSN={partial_read_resp_psn}')
        next_request_psn = (partial_read_resp_psn + remaining_read_resp_pkt_num) % MAX_PSN
        return (WC_STATUS.SUCCESS, next_request_psn)

    def ack_send_or_write_req(self, psn_to_ack):
        pending_wr_ssn, pkt_to_ack = self.req_pkt_psn_wr_ssn_dict[psn_to_ack]
        rc_op = pkt_to_ack[BTH].opcode
        
        if rc_op == RC.RDMA_READ_REQUEST or RC.atomic(rc_op):
            # This function is only to explicit or implicit ACK send and write, not for read or atomic
            return False

        # Generate CQE if the packet to ack is the last one
        if RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            send_or_write_wr = self.get_pending_wr(pending_wr_ssn)
            # Generate CQE for each acked send or write WR
            cqe = CQE(
                wr_id = send_or_write_wr.id(),
                status = WC_STATUS.SUCCESS,
                opcode = WC_OPCODE.from_rc_op(rc_op),
                length = send_or_write_wr.len(),
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = EMPTY_WC_FLAG, # Requester side CQE no need to handle IBV_WC_WITH_IMM or IBV_WC_WITH_INV
            )
            # No need to retire top RQ element since this is request side, no RQ logic involved
            self.cq().push(cqe)
            # Delete completed send or write WR
            self.delete_wr(pending_wr_ssn)
        return True

    def coalesce_ack(self, psn_upper_limit): # psn_upper_limit not included
        assert Util.psn_compare(self.mpsn(), psn_upper_limit, self.npsn()) <= 0, 'min_unacked_psn shoud <= psn_upper_limit'
        implicit_ack_pkt_num = 0
        for unacked_psn in Util.psn_range(self.mpsn(), psn_upper_limit):
            ack_res = self.ack_send_or_write_req(unacked_psn)
            if not ack_res: # unacked_psn is either read or atomic request, coalesce ack should stop
                self.update_min_unacked_psn(min_unacked_psn = unacked_psn)
                return (False, unacked_psn, implicit_ack_pkt_num) # coalesce_ack enountered implicit NAK
            implicit_ack_pkt_num += 1
        self.update_min_unacked_psn(min_unacked_psn = psn_upper_limit)
        return (True, psn_upper_limit, implicit_ack_pkt_num) # coalesce_ack success

    def goto_err_state(self, err_pkt_psn, err_wc_status):
        self.qp.modify_qp(qps = QPS.ERR)
        # Explicit NAK corresponding request
        nak_ssn, nak_pkt = self.req_pkt_psn_wr_ssn_dict[err_pkt_psn]
        nak_sr = self.get_pending_wr(nak_ssn)
        nak_cqe = CQE(
            wr_id = nak_sr.id(),
            status = err_wc_status,
            opcode = WC_OPCODE.from_wr_op(nak_sr.id()),
            length = nak_sr.len(),
            qpn = self.sqpn(),
            src_qp = self.dqpn(),
            wc_flags = EMPTY_WC_FLAG,
        )
        self.cq.push(nak_cqe)
        self.delete_wr(nak_ssn) # Delete the NAK specified WR

        # All pending processing send WR will be completed with flush in error
        self.flush()
        # All submitted WR in SQ/RD will be completed with flush in error
        self.qp.flush()

    def handle_ack(self, ack, retry_handler = None):
        assert ack[BTH].opcode == RC.ACKNOWLEDGE, 'should be ack response'

        # AETH.code {0: "ACK", 1: "RNR", 2: "RSVD", 3: "NAK"}
        if ack[AETH].code == 0: # ACK
            ack_res = self.ack_send_or_write_req(ack[BTH].psn)
            assert ack_res, 'should successfully ack send or write request'
            return (WC_STATUS.SUCCESS, Util.next_psn(ack[BTH].psn)) # ACK should update unacked_min_psn

        elif ack[AETH].code == 3 and ack[AETH].value in [1, 2, 3]: # NAK invalid request / remote access / remote operation error, no retry
            err_pkt_psn = ack[AETH].value
            err_wc_status = WC_STATUS.from_nak(ack[AETH].value)
            return (err_wc_status, err_pkt_psn)

        elif ack[AETH].code == 1: # RNR NAK, should retry
            rnr_psn = ack[BTH].psn
            rnr_wait_timer = ack[AETH].value
            if self.qp.min_rnr_timer == 0: # 0 represents the largest RNR timer 655.36ms
                rnr_wait_timer = self.qp.min_rnr_timer
            elif self.min_rnr_timer > ack[AETH].value:
                self.min_rnr_timer # Choose the larger RNR timer
            logging.debug(f'SQ={self.sqpn()} received RNR NAK with PSN={rnr_psn} and wait time={rnr_wait_timer}, min_rnr_timer={self.qp.min_rnr_timer}')
            # Handle RNR NAK wait time
            wait_time_secs = Util.rnr_timer_to_ns(rnr_wait_timer) / 1_000_000_000
            time.sleep(wait_time_secs) # Wait the time specified by rnr_wait_timer before retry

            # TODO: double check RNR retry only the specified request packet or retry all thereafter
            return self.retry_one_wr_by_psn(
                #ssn_to_retry = rnr_wr_ssn,
                psn_begin_retry = rnr_psn,
                retry_type = RETRY_TYPE.RNR,
                retry_handler = retry_handler,
            )

        elif (ack[AETH].code == 3 and ack[AETH].value == 0): # NAK seq error, should retry
            seq_err_psn = ack[BTH].psn
            logging.debug(f'SQ={self.sqpn()} received NAK SEQ ERR with PSN={seq_err_psn}')
            return self.retry_pkts(
                psn_begin_retry = seq_err_psn,
                retry_type = RETRY_TYPE.SEQ,
                retry_handler= retry_handler,
            ) # retry remaining request if any

        else:
            logging.info('received reserved AETH code or reserved AETH NAK value or unsported AETH NAK value: ' + ask.show(dump = True))
            return (WC_STATUS.SUCCESS, ack[BTH].psn) # TODO: check whether SQ discard illegal ACK or not

    def handle_read_resp(self, read_resp):
        rc_op = read_resp[BTH].opcode
        read_resp_psn = read_resp[BTH].psn
        read_resp_padcount = read_resp[BTH].padcount

        assert RC.read_resp(rc_op), 'should be read response'
        # Handle locally detected error: Length error / Requester Class B
        if not Util.check_pkt_size(self.qp.mtu(), read_resp):
            logging.error('received read response packet size illegal')
            return (WC_STATUS.LOC_LEN_ERR, read_resp_psn)
        # Handle locally detected error: Local Memory Protection Error / Requester Class B
        if not Util.check_op_with_access_flags(rc_op, self.qp.flags()):
            logging.error('received packet has opcode without proper permission')
            return (WC_STATUS.LOC_PROT_ERR, read_resp_psn)

        read_wr_ssn, orig_read_req_psn = self.read_resp_psn_wr_ssn_dict[read_resp_psn]
        read_wr = self.get_pending_wr(read_wr_ssn)
        read_offset, resp_pkt_psn_dict = self.pending_read_ctx_dict[read_wr_ssn]

        read_dlen = read_wr.len()
        read_laddr = read_wr.laddr()
        if Raw in read_resp:
            read_lkey = read_wr.lkey()
            # Handle locally detected error: Local Memory Protection Error / Requester Class B
            if not self.qp.pd.validate_mr(rc_op, read_lkey, read_laddr, read_dlen):
                logging.error('read response local access error to MR')
                return (WC_STATUS.LOC_PROT_ERR, read_resp_psn)
            read_mr = self.qp.pd.get_mr(read_lkey)
            read_offset += Util.write_to_mr(
                dst_mr = read_mr,
                write_to_mr_addr = read_laddr,
                data_pkt = read_resp,
            )
        # Update pending_read_ctx_dict
        self.pending_read_ctx_dict[read_wr_ssn] = (read_offset, resp_pkt_psn_dict)

        if rc_op == RC.RDMA_READ_RESPONSE_LAST or rc_op == RC.RDMA_READ_RESPONSE_ONLY:
            # Handle locally detected error: Length error / Requester Class B
            if read_offset != read_dlen:
                logging.error('read response data size not match DMA length')
                return (WC_STATUS.LOC_LEN_ERR, read_resp_psn)

            # Generate CQE for read response
            read_cqe = CQE(
                wr_id = read_wr.id(),
                status = WC_STATUS.SUCCESS,
                opcode = WC_OPCODE.from_rc_op(rc_op),
                length = read_dlen,
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = EMPTY_WC_FLAG,
            )
            # No need to retire top RQ element since this is requester side, no RQ logic involved
            self.cq().push(read_cqe)
            # Delete completed read WR
            self.delete_wr(read_wr_ssn)
        return (WC_STATUS.SUCCESS, Util.next_psn(read_resp_psn))

    def handle_atomic_ack(self, atomic_ack):
        rc_op = atomic_ack[BTH].opcode
        atomic_ack_psn = atomic_ack[BTH].psn
        assert rc_op == RC.ATOMIC_ACKNOWLEDGE, 'should be atomic ack'
        # TODO: handle atomic NAK, does atomic have NAK?
        assert atomic_ack[AETH].code == 0, 'atomic ack is NAK'

        atomic_wr_ssn, atomic_req = self.req_pkt_psn_wr_ssn_dict[atomic_ack_psn]
        atomic_wr = self.get_pending_wr(atomic_wr_ssn)
        atomic_laddr = atomic_wr.laddr()
        atomic_lkey = atomic_wr.lkey()

        # Handle locally detected error: Local Memory Protection Error / Requester Class B
        if not self.qp.pd.validate_mr(rc_op, atomic_lkey, atomic_laddr, ATOMIC_BYTE_SIZE):
            logging.error('atomic response local access error to MR')
            return (WC_STATUS.LOC_PROT_ERR, atomic_ack_psn)
        # Because bind_layers(AETH, AtomicAckETH) is not work, so use Raw instead of AtomicAckETH
        if len(atomic_ack[Raw]) != ATOMIC_BYTE_SIZE:
            logging.error('AtomicAckETH size not correct')
            return (WC_STATUS.LOC_LEN_ERR, atomic_ack_psn)
        atomic_mr = self.qp.pd.get_mr(atomic_lkey)
        atomic_mr.write(byte_data = atomic_ack[Raw].load, addr = atomic_laddr)
        atomic_cqe = CQE(
            wr_id = atomic_wr.id(),
            status = WC_STATUS.SUCCESS,
            opcode = WC_OPCODE.from_wr_op(atomic_wr.op()),
            length = ATOMIC_BYTE_SIZE,
            qpn = self.sqpn(),
            src_qp = self.dqpn(),
            wc_flags = EMPTY_WC_FLAG,
        )
        # No need to retire top RQ element since this is request side, no RQ logic involved
        self.cq().push(atomic_cqe)
        # Delete completed atomic WR
        self.delete_wr(atomic_wr_ssn)
        return (WC_STATUS.SUCCESS, Util.next_psn(atomic_ack_psn))

class SQ:
    def __init__(self, qp, cq, sq_psn, sq_draining = False):
        self.sq = []
        self.qp = qp
        self.cq = cq
        self.sq_psn = sq_psn % MAX_PSN
        self.ssn = 1
        self.sq_draining = sq_draining

    def modify(self,
        sq_psn = None,
        sq_draining = None,
    ):
        if sq_psn is not None:
            self.sq_psn = sq_psn % MAX_PSN
            #self.min_unacked_psn = self.sq_psn # min_unacked_psn should be updated each time sq_psn updated
        if sq_draining is not None:
            self.sq_draining = sq_draining

    def push(self, wr):
        wr_op = wr.op()
        # TODO: handle immediate errors, unsupported opcode
        assert WR_OPCODE.send(wr_op) or WR_OPCODE.write(wr_op) or WR_OPCODE.atomic(wr_op) or wr_op == WR_OPCODE.RDMA_READ, 'send WR has unsupported opcode'
        # TODO: handle immediate errors
        if wr.op() in [WR_OPCODE.SEND_WITH_IMM, WR_OPCODE.SEND_WITH_INV, WR_OPCODE.RDMA_WRITE_WITH_IMM]:
            assert wr.imm_data_or_inv_rkey(), 'send/write with immediate data or send with invalidate requires send WR has imm_data_or_inv_rkey'
        if WR_OPCODE.atomic(wr.op()):
            assert wr.len() >= ATOMIC_BYTE_SIZE, 'atomic WR has no enough buffer length to receive atomic response'
        if wr.len() > 0:
            local_key = wr.lkey()
            # TODO: handle immediate error
            assert self.qp.pd.has_mr(local_key), 'send WR has invalid lkey'
            mr = self.qp.pd.get_mr(local_key)
            # TODO: handle immediate error
            assert wr.laddr() + wr.len() <= mr.len(), 'send WR local SG is not within its MR'
        
        self.sq.append(wr)

    def pop(self):
        assert not self.sq_draining, 'SQ is draining, cannot pop WQE'
        wr = self.sq.pop(0)
        cssn = self.ssn
        self.ssn = (self.ssn + 1) % MAX_SSN
        return (wr, cssn)

    def empty(self):
        return not bool(self.sq)

    def sqpn(self):
        return self.qp.qpn()

    def dqpn(self):
        return self.qp.dqpn()

    def send_req_pkt(self, wr_ssn, req_pkt):
        self.qp.soc.send_req_pkt(wr_ssn, req_pkt)

    def process_send_req(self, sr, cssn):
        assert WR_OPCODE.send(sr.op()), 'should be send operation'
        addr = sr.laddr()
        send_size = sr.len()
        send_data = b''
        if send_size:
            mr = self.qp.pd.get_mr(sr.lkey())
            send_data = mr.read(addr = addr, size = send_size)

        send_req_pkt_num = Util.compute_wr_pkt_num(sr.len(), self.qp.mtu())
        cpsn = self.sq_psn
        dqpn = self.dqpn()
        ackreq = True if SEND_FLAGS.SIGNALED & sr.flags() else False
        solicited = True if SEND_FLAGS.SOLICITED & sr.flags() else False

        if send_req_pkt_num > 1:
            send_bth = BTH(
                opcode = RC.SEND_FIRST,
                psn = cpsn,
                dqpn = dqpn,
                ackreq = False,
                solicited = False,
            )
            send_req = send_bth/Raw(load = send_data[0 : self.qp.mtu()])
            self.send_req_pkt(cssn, send_req)

            send_req_mid_pkt_num = send_req_pkt_num - 2
            for i in range(send_req_mid_pkt_num):
                send_bth = BTH(
                    opcode = RC.SEND_MIDDLE,
                    psn = cpsn + i + 1,
                    dqpn = dqpn,
                    ackreq = False,
                    solicited = False,
                )
                send_req = send_bth/Raw(load = send_data[((i + 1) * self.qp.mtu()) : ((i + 2) * self.qp.mtu())])
                self.send_req_pkt(cssn, send_req)

        rc_op = None
        if send_req_pkt_num == 1:
            if sr.op() == WR_OPCODE.SEND_WITH_IMM:
                rc_op = RC.SEND_ONLY_WITH_IMMEDIATE
            elif sr.op() == WR_OPCODE.SEND_WITH_INV:
                rc_op = RC.SEND_ONLY_WITH_INVALIDATE
            else:
                rc_op = RC.SEND_ONLY
        else:
            if sr.op() == WR_OPCODE.SEND_WITH_IMM:
                rc_op = RC.SEND_LAST_WITH_IMMEDIATE
            elif sr.op() == WR_OPCODE.SEND_WITH_INV:
                rc_op = RC.SEND_LAST_WITH_INVALIDATE
            else:
                rc_op = RC.SEND_LAST
        send_bth = BTH(
            opcode = rc_op,
            psn = cpsn + send_req_pkt_num - 1,
            dqpn = dqpn,
            ackreq = ackreq,
            solicited = solicited,
        )
        send_req = None
        if RC.has_imm(rc_op):
            imm_data = ImmDt(data = sr.imm_data_or_inv_rkey())
            send_req = send_bth/imm_data
        elif RC.has_inv(rc_op):
            send_ieth = IETH(rkey = sr.imm_data_or_inv_rkey())
            send_req = send_bth/send_ieth
        else:
            send_req = send_bth
        if send_size > 0:
            raw_pkt = Raw(load = send_data[((send_req_pkt_num - 1) * self.qp.mtu()) : send_size])
            send_req = send_req/raw_pkt
        self.send_req_pkt(cssn, send_req)
        self.sq_psn = (self.sq_psn + send_req_pkt_num) % MAX_PSN

    def process_write_req(self, sr, cssn):
        assert WR_OPCODE.write(sr.op()), 'should be write operation'
        addr = sr.laddr()
        write_size = sr.len()
        write_data = b''
        if write_size:
            mr = self.qp.pd.get_mr(sr.lkey())
            write_data = mr.read(addr = addr, size = write_size)

        write_req_pkt_num = Util.compute_wr_pkt_num(write_size, self.qp.mtu())
        cpsn = self.sq_psn
        dqpn = self.dqpn()
        ackreq = True if SEND_FLAGS.SIGNALED & sr.flags() else False
        solicited = False

        write_reth = RETH(va = sr.raddr(), rkey = sr.rkey(), dlen = write_size)
        if write_req_pkt_num > 1:
            write_bth = BTH(
                opcode = RC.RDMA_WRITE_FIRST,
                psn = cpsn,
                dqpn = dqpn,
                ackreq = False,
                solicited = False,
            )
            write_req = write_bth/write_reth/Raw(load = write_data[0 : self.qp.mtu()])
            self.send_req_pkt(cssn, write_req)

            write_req_mid_pkt_num = write_req_pkt_num - 2
            for i in range(write_req_mid_pkt_num):
                write_bth = BTH(
                    opcode = RC.RDMA_WRITE_MIDDLE,
                    psn = cpsn + i + 1,
                    dqpn = dqpn,
                    ackreq = False,
                    solicited = False,
                )
                write_req = write_bth/Raw(load = write_data[((i + 1) * self.qp.mtu()) : ((i + 2) * self.qp.mtu())])
                self.send_req_pkt(cssn, write_req)

        rc_op = None
        solicited = False
        if write_req_pkt_num == 1:
            if sr.op() == WR_OPCODE.RDMA_WRITE_WITH_IMM:
                rc_op = RC.RDMA_WRITE_ONLY_WITH_IMMEDIATE
                solicited = True if SEND_FLAGS.SOLICITED & sr.flags() else False
            else:
                rc_op = RC.RDMA_WRITE_ONLY
        else:
            if sr.op() == WR_OPCODE.RDMA_WRITE_WITH_IMM:
                rc_op = RC.RDMA_WRITE_LAST_WITH_IMMEDIATE
                solicited = True if SEND_FLAGS.SOLICITED & sr.flags() else False
            else:
                rc_op = RC.RDMA_WRITE_LAST
        write_bth = BTH(
            opcode = rc_op,
            psn = cpsn + write_req_pkt_num - 1,
            dqpn = dqpn,
            ackreq = ackreq,
            solicited = solicited,
        )
        write_req = None
        if RC.only_req_pkt(rc_op):
            if RC.has_imm(rc_op):
                # RDMA_WRITE_ONLY_WITH_IMMEDIATE use RETHImmDt, instead of RETH/ImmDt
                reth_imm_data = RETHImmDt(va = sr.raddr(), rkey = sr.rkey(), dlen = write_size, data = sr.imm_data_or_inv_rkey())
                write_req = write_bth/reth_imm_data
            else:
                write_req = write_bth/write_reth
        else:
            if RC.has_imm(rc_op):
                imm_data = ImmDt(data = sr.imm_data_or_inv_rkey())
                write_req = write_bth/imm_data
            else:
                write_req = write_bth
        if write_size > 0:
            raw_pkt = Raw(load = write_data[((write_req_pkt_num - 1) * self.qp.mtu()) : write_size])
            write_req = write_req/raw_pkt
        self.send_req_pkt(cssn, write_req)
        self.sq_psn = (self.sq_psn + write_req_pkt_num) % MAX_PSN

    def process_read_req(self, sr, cssn):
        assert sr.op() == WR_OPCODE.RDMA_READ, 'should be read operation'
        # TODO: locally detected error: Local Memory Protection / Requester Class B
        assert ACCESS_FLAGS.LOCAL_WRITE & self.qp.flags(), 'read op should have write permission to local MR'

        read_size = sr.len()
        read_resp_pkt_num = Util.compute_wr_pkt_num(read_size, self.qp.mtu())
        cpsn = self.sq_psn
        dqpn = self.dqpn()

        read_bth = BTH(
            opcode = RC.RDMA_READ_REQUEST,
            psn = cpsn,
            dqpn = dqpn,
            ackreq = True,
        )
        read_reth = RETH(va = sr.raddr(), rkey = sr.rkey(), dlen = read_size)
        read_req = read_bth/read_reth
        
        self.qp.soc.send_read_req_pkt(cssn, read_req, read_resp_pkt_num)
        self.sq_psn = (self.sq_psn + read_resp_pkt_num) % MAX_PSN

    def process_atomic_req(self, sr, cssn):
        assert WR_OPCODE.atomic(sr.op()), 'should be atomic operation'
        # TODO: handle locally detected error: Local Memory Protection / Requester Class B
        assert ACCESS_FLAGS.LOCAL_WRITE & self.qp.flags(), 'atomic op should have write permission to local MR'

        rc_op = RC.COMPARE_SWAP if sr.op() == WR_OPCODE.ATOMIC_CMP_AND_SWP else RC.FETCH_ADD
        cpsn = self.sq_psn
        dqpn = self.dqpn()
        atomic_bth = BTH(
            opcode = rc_op,
            psn = cpsn,
            dqpn = dqpn,
            ackreq = True,
        )
        atomic_eth = AtomicETH(
            va = sr.raddr(),
            rkey = sr.rkey(),
            comp = sr.comp(),
            swap = sr.swap(),
        )
        atomic_req = atomic_bth/atomic_eth
        self.send_req_pkt(cssn, atomic_req)
        self.sq_psn = Util.next_psn(self.sq_psn)

class RQ:
    def __init__(self, qp, cq, rq_psn):
        self.rq = []
        self.qp = qp
        self.cq = cq
        self.rq_psn = rq_psn % MAX_PSN
        self.msn = 0

        self.resp_pkt_dict = {}
        self.pre_pkt_op = None

        self.cur_send_req_ctx = None
        self.cur_write_req_ctx = None

        self.rnr_nak_wait_clear_ts_ns = 0
        self.nak_seq_err_clear = True

    def modify(self, rq_psn = None):
        if rq_psn is not None:
            self.rq_psn = rq_psn % MAX_PSN

    def push(self, wr):
        self.rq.append(wr)

    def pop(self):
        return self.rq.pop(0)

    def empty(self):
        return not bool(self.rq)

    def sqpn(self):
        return self.qp.qpn()

    def dqpn(self):
        return self.qp.dqpn()

    def is_expected_req(self, req_psn):
        return req_psn == self.rq_psn

    def handle_dup_or_illegal_req(self, req):
        req_psn = req[BTH].psn
        psn_comp_res = Util.psn_compare(self.rq_psn, req_psn, self.rq_psn)
        assert psn_comp_res != 0, 'should handle duplicate or illegal request'
        if psn_comp_res > 0: # Dup req
            logging.debug(f'RQ={self.sqpn()} received duplicate request: ' + req.show(dump = True))
            rc_op = req[BTH].opcode
            if RC.send(rc_op) or RC.write(rc_op):
                dup_resp = self.resp_pkt_dict[req_psn]
                dup_resp[BTH].psn = self.rq_psn # Dup requst response has latest PSN
                self.send_pkt(dup_resp, save_pkt = False)
            elif rc_op == RC.RDMA_READ_REQUEST:
                self.handle_read_req(self, req, update_epsn = False)
            elif RC.atomic(rc_op):
                # TODO: check the dup atomic request is the same as before
                dup_resp = self.resp_pkt_dict[req_psn]
                if AtomicAckETH in dup_resp:
                    self.send_pkt(dup_resp, save_pkt = False)
                else:
                    logging.debug(f'RQ={self.sqpn()} received duplicate atomic request: ' + req.show(dump = True) + ', but the response was not match: ' + dup_resp.show(dump = True))
        else:
            # Handle NAK sequence error: Out of Sequence Request Packet / Responder Class B
            logging.debug(f'RQ={self.sqpn()} had sequence error, ePSN={self.rq_psn} but received request: ' + req.show(dump = True))
            self.process_nak_seq_err()

    def send_pkt(self, resp, save_pkt = True):
        if not self.dqpn():
            raise Exception(f'RQ={self.sqpn()} has no destination QPN')
        elif not self.qp.dgid():
            raise Exception(f'RQ={self.sqpn()} has no destination GID')

        #dst_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(self.dgid))
        dst_ipv6 = socket.inet_ntop(socket.AF_INET6, self.qp.dgid())
        dst_ipv4 = dst_ipv6.replace('::ffff:', '')
        dst_ip = dst_ipv6 if self.qp.use_ipv6 else dst_ipv4

        pkt = IP(dst=dst_ip)/UDP(dport=ROCE_PORT, sport=self.sqpn())/resp
        cpsn = pkt[BTH].psn
        if save_pkt:
            self.resp_pkt_dict[cpsn] = pkt
        logging.debug(f'RQ={self.sqpn()} send to IP={dst_ip} a response: ' + pkt.show(dump = True))
        send(pkt)

    def recv_pkt(self, pkt, retry_handler = None):
        logging.debug(f'RQ={self.sqpn()} received packet with length={len(pkt)}: ' + pkt.show(dump = True) + f', previous operation is: {self.pre_pkt_op}')
        rc_op = pkt[BTH].opcode

        # TODO: handle head verification
        assert pkt[BTH].dqpn == self.qp.qpn(), 'received packet QPN not match'
        assert pkt[BTH].opcode < 0x20, 'only RC supported'
        assert pkt[BTH].version == 0, 'header version must be zero'
        assert pkt[BTH].pkey == self.qp.pkey(), 'received packet PKEY not match' # TODO: handle PKEY match rule

        # Handle invalid request error: Out of Sequence OpCode / Responder Class C
        if not Util.check_pre_cur_ops(self.pre_pkt_op, rc_op):
            logging.error('previous and current opcodes are not legal')
            return self.process_nak_err(req = pkt, err_wc_status = WC_STATUS.REM_INV_REQ_ERR)

        if RC.request(rc_op):
            # Handle invalid request error: Length errors / Responder Class C
            if not Util.check_pkt_size(self.qp.mtu(), pkt):
                logging.error('received packet size illegal')
                return self.process_nak_err(req = pkt, err_wc_status = WC_STATUS.REM_INV_REQ_ERR)
            # Handle invalid request error: Unsupported or Reserved OpCode / Responder Class C
            if not Util.check_op_with_access_flags(rc_op, self.qp.flags()):
                logging.error('received packet has opcode without proper permission')
                return self.process_nak_err(req = pkt, err_wc_status = WC_STATUS.REM_INV_REQ_ERR)

            if self.is_expected_req(pkt[BTH].psn):
                self.nak_seq_err_clear = True # RQ received request matches its ePSN and clear any previous NAK sequence error
                if RC.send(rc_op):
                    self.handle_send_req(pkt)
                elif RC.write(rc_op):
                    self.handle_write_req(pkt)
                elif rc_op == RC.RDMA_READ_REQUEST:
                    self.handle_read_req(pkt)
                elif RC.atomic(rc_op):
                    self.handle_atomic_req(pkt)
                else:
                    raise Exception(f'unknown request opcode={rc_op}')
                self.rq_psn = self.rq_psn % MAX_PSN
            else:
                self.handle_dup_or_illegal_req(pkt)
            self.pre_pkt_op = rc_op # TODO: only update pre_pkt_op for expected packet?
        elif RC.response(rc_op):
            if self.qp.soc.is_expected_resp(pkt[BTH].psn):
                self.qp.soc.handle_expected_resp(pkt, retry_handler)
                self.pre_pkt_op = rc_op
            else:
                # Do not update pre_pkt_op for duplicate packet or ghost response
                self.qp.soc.handle_dup_or_illegal_resp(pkt)
        else:
            raise Exception(f'received unsupported opcode={rc_op}')

    def handle_send_req(self, send_req):
        rc_op = send_req[BTH].opcode
        assert RC.send(rc_op), 'should be send request'

        if RC.first_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            # Handle RNR NAK: Resources Not Ready Error / Responder Class B
            if self.empty():
                logging.debug(f'RQ={self.sqpn()} is empty, response RNR NAK to send request')
                return self.process_nak_rnr(send_req)
            rr = self.pop()
            self.cur_send_req_ctx = (rr, 0)

        rr, send_offset = self.cur_send_req_ctx
        send_addr = rr.addr() + send_offset
        data_size = 0
        if Raw in send_req:
            data_size = len(send_req[Raw].load)
            # Handle invalid request error: Length errors / Responder Class C
            if not self.qp.pd.validate_mr(rc_op, rr.lkey(), send_addr, data_size):
                logging.error('no enough receive buffer for send request')
                return self.process_nak_err(req = write_req, err_wc_status = WC_STATUS.REM_INV_REQ_ERR, nak_wr = rr)
            send_mr = self.qp.pd.get_mr(rr.lkey())
            send_offset += Util.write_to_mr(dst_mr = send_mr, write_to_mr_addr = send_addr, data_pkt = send_req)
        self.cur_send_req_ctx = (rr, send_offset)

        if RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            self.msn = (self.msn + 1) % MAX_MSN
            self.cur_send_req_ctx = None # Reset cur_send_req_ctx to None after receive the last or only send request

            cqe_wc_flags = EMPTY_WC_FLAG
            cqe_imm_data_or_inv_rkey = None
            if RC.has_imm(rc_op):
                cqe_wc_flags |= WC_FLAGS.WITH_IMM
                cqe_imm_data_or_inv_rkey = send_req[ImmDt].data
            elif RC.has_inv(rc_op):
                cqe_wc_flags |= WC_FLAGS.WITH_INV
                cqe_imm_data_or_inv_rkey = send_req[IETH].rkey # TODO: handle rkey invalidation
            # Generate CQE for received send request
            cqe = CQE(
                wr_id = rr.id(),
                status = WC_STATUS.SUCCESS,
                opcode = WC_OPCODE.from_rc_op(rc_op),
                length = send_offset,
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = cqe_wc_flags,
                imm_data_or_inv_rkey = cqe_imm_data_or_inv_rkey,
            )
            self.cq.push(cqe)

            if send_req[BTH].solicited:
                # TODO: handle solicited event
                TODO
        self.rq_psn = Util.next_psn(self.rq_psn) # Update ePSN
        if send_req[BTH].ackreq:
            self.process_ack(send_req)

    def handle_write_req(self, write_req):
        rc_op = write_req[BTH].opcode
        assert RC.write(rc_op), 'should be write request'

        write_req_rkey = None
        write_req_addr = None
        write_req_dlen = None
        if RC.first_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            if RC.has_imm(rc_op):
                write_req_rkey = write_req[RETHImmDt].rkey
                write_req_addr = write_req[RETHImmDt].va
                write_req_dlen = write_req[RETHImmDt].dlen
            else:
                write_req_rkey = write_req[RETH].rkey
                write_req_addr = write_req[RETH].va
                write_req_dlen = write_req[RETH].dlen

            write_mr = None
            if write_req_dlen > 0:
                # Handle remote access error: Responder Class C
                if not self.qp.pd.validate_mr(rc_op, write_req_rkey, write_req_addr, write_req_dlen):
                    logging.error('write request remote access error')
                    # TODO: double check write with imm error case, it should report write length error,
                    # before consume a RR and generate a CQE with error status
                    return self.process_nak_err(req = write_req, err_wc_status = WC_STATUS.REM_ACCESS_ERR)

                write_mr = self.qp.pd.get_mr(write_req_rkey)
            else:
                assert Raw not in write_req and RC.only_req_pkt(rc_op), 'write request with DMA length as 0 should have no data'
            self.cur_write_req_ctx = (write_mr, write_req_dlen, write_req_addr, 0)

        write_mr, write_dlen, write_addr, write_offset = self.cur_write_req_ctx
        if Raw in write_req:
            write_offset += Util.write_to_mr(dst_mr = write_mr, write_to_mr_addr = write_addr, data_pkt = write_req)
        # Update write_offset to cur_write_req_ctx
        self.cur_write_req_ctx = (write_mr, write_dlen, write_addr, write_offset)

        if RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            # Handle invalid request error: Length error / Responder Class C
            if write_offset != write_dlen:
                logging.error('write request data size not match DMA length')
                # TODO: double check write with imm error case, it should report write length error,
                # before consume a RR and generate a CQE with error status
                return self.process_nak_err(req = write_req, err_wc_status = WC_STATUS.REM_INV_REQ_ERR)

            self.msn = (self.msn + 1) % MAX_MSN
            self.cur_write_req_ctx = None # Reset cur_write_req_ctx to None after receive the last or only write request

            if RC.has_imm(rc_op):
                cqe_wc_flags = WC_FLAGS.WITH_IMM
                cqe_imm_data = write_req[RETHImmDt].data
                # Handle RNR NAK: Resources Not Ready Error / Responder Class B
                if self.empty():
                    logging.debug(f'RQ={self.sqpn()} is empty but write with immediate data needs to consume a receive WR')
                    return self.process_nak_rnr(write_req)
                rr = self.pop()
                # Generate CQE for received send request
                cqe = CQE(
                    wr_id = rr.id(),
                    status = WC_STATUS.SUCCESS,
                    opcode = WC_OPCODE.from_rc_op(rc_op),
                    length = write_dlen,
                    qpn = self.sqpn(),
                    src_qp = self.dqpn(),
                    wc_flags = cqe_wc_flags,
                    imm_data_or_inv_rkey = cqe_imm_data,
                )
                self.cq.push(cqe)

                if write_req[BTH].solicited:
                    # TODO: handle solicited event
                    TODO
        self.rq_psn = Util.next_psn(self.rq_psn) # Update ePSN
        if write_req[BTH].ackreq:
            self.process_ack(write_req)

    def handle_read_req(self, read_req, update_epsn = True):
        rc_op = read_req[BTH].opcode
        assert rc_op == RC.RDMA_READ_REQUEST, 'should be read request'

        read_req_size = read_req[RETH].dlen
        read_req_addr = read_req[RETH].va
        read_req_rkey = read_req[RETH].rkey

        read_data = None
        if read_req_size > 0:
            # Handle remote access error: Responder Class C
            if not self.qp.pd.validate_mr(rc_op, read_req_rkey, read_req_addr, read_req_size):
                logging.error('read request remote access error')
                return self.process_nak_err(req = read_req, err_wc_status = WC_STATUS.REM_ACCESS_ERR)
            read_mr = self.qp.pd.get_mr(read_req_rkey)
            read_data = read_mr.read(addr = read_req_addr, size = read_req_size)

        cpsn = self.rq_psn
        dqpn = self.dqpn()
        self.msn = (self.msn + 1) % MAX_MSN
        read_resp_pkt_num = Util.compute_wr_pkt_num(read_req_size, self.qp.mtu())
        read_aeth = AETH(code = 'ACK', value = CREDIT_CNT_INVALID, msn = self.msn)
        if read_resp_pkt_num > 1:
            read_resp_bth = BTH(
                opcode = RC.RDMA_READ_RESPONSE_FIRST,
                psn = cpsn,
                dqpn = dqpn,
            )
            read_resp = read_resp_bth/read_aeth/Raw(load = read_data[0 : self.qp.mtu()])
            self.send_pkt(read_resp, save_pkt = False)

            read_resp_mid_pkt_num = read_resp_pkt_num - 2
            for i in range(read_resp_mid_pkt_num):
                read_resp_bth = BTH(
                    opcode = RC.RDMA_READ_RESPONSE_MIDDLE,
                    psn = cpsn + i + 1,
                    dqpn = dqpn,
                )
                read_resp = read_resp_bth/Raw(load = read_data[((i + 1) * self.qp.mtu()) : ((i + 2) * self.qp.mtu())])
                self.send_pkt(read_resp, save_pkt = False)

        rc_op = None
        if read_resp_pkt_num == 1:
            rc_op = RC.RDMA_READ_RESPONSE_ONLY
        else:
            rc_op = RC.RDMA_READ_RESPONSE_LAST
        read_resp_bth = BTH(
            opcode = rc_op,
            psn = cpsn + read_resp_pkt_num - 1,
            dqpn = dqpn,
        )
        read_resp = read_resp_bth/read_aeth
        if read_req_size > 0:
            read_resp = read_resp/Raw(load = read_data[((read_resp_pkt_num - 1) * self.qp.mtu()) : read_req_size])
        self.send_pkt(read_resp, save_pkt = False)
        if update_epsn:
            self.rq_psn = (self.rq_psn + read_resp_pkt_num) % MAX_PSN

    def handle_atomic_req(self, atomic_req):
        rc_op = atomic_req[BTH].opcode
        assert RC.atomic(rc_op), 'should be atomic request'

        atomic_req_rkey = atomic_req[AtomicETH].rkey
        atomic_req_addr = atomic_req[AtomicETH].va
        # Handle remote access error: Responder Class C
        if not self.qp.pd.validate_mr(rc_op, atomic_req_rkey, atomic_req_addr, ATOMIC_BYTE_SIZE):
            logging.error('atomic request remote access error')
            return self.process_nak_err(req = atomic_req, err_wc_status = WC_STATUS.REM_ACCESS_ERR)
        mr = self.qp.pd.get_mr(atomic_req_rkey)

        cpsn = self.rq_psn
        dqpn = self.dqpn()
        self.msn = (self.msn + 1) % MAX_MSN

        # Handle invalid request error: Misaligned ATOMIC / Responder Class C
        if not Util.check_addr_aligned(addr = atomic_req[AtomicETH].va, mr = mr):
            logging.error('atomic request address is not 8-byte aligned')
            return self.process_nak_err(req = atomic_req, err_wc_status = WC_STATUS.REM_INV_REQ_ERR)

        orig = int.from_bytes(mr.read(addr = atomic_req_addr, size = ATOMIC_BYTE_SIZE), sys.byteorder)
        comp = atomic_req[AtomicETH].comp
        swap = atomic_req[AtomicETH].swap
        if rc_op == RC.COMPARE_SWAP:
            if orig == comp:
                mr.write(byte_data = swap.to_bytes(ATOMIC_BYTE_SIZE, sys.byteorder), addr = atomic_req_addr)
        else:
            mr.write(byte_data = (orig + comp).to_bytes(ATOMIC_BYTE_SIZE, sys.byteorder), addr = atomic_req_addr)

        ack_bth = BTH(
            opcode = RC.ATOMIC_ACKNOWLEDGE,
            psn = cpsn,
            dqpn = dqpn,
        )
        ack_aeth = AETH(code = 'ACK', value = CREDIT_CNT_INVALID, msn = self.msn)
        atomic_ack_eth = AtomicAckETH(orig = orig)
        atomic_ack = ack_bth/ack_aeth/atomic_ack_eth
        self.send_pkt(atomic_ack)
        self.rq_psn = Util.next_psn(self.rq_psn) # Update ePSN

    def process_ack(self, req):
        assert req[BTH].ackreq, 'received request should ask for ack response'
        ack_bth = BTH(
            opcode = RC.ACKNOWLEDGE,
            psn = req[BTH].psn,
            dqpn = self.dqpn(),
        )
        # TODO: support RQ flow control
        ack = ack_bth/AETH(code = 'ACK', value = CREDIT_CNT_INVALID, msn = self.msn)
        self.send_pkt(ack)

    def process_nak_rnr(self, req):
        cur_ts_ns = time.time_ns()
        if cur_ts_ns > self.rnr_nak_wait_clear_ts_ns:
            rnr_wait_timer = self.qp.min_rnr_timer
            rnr_nak_bth = BTH(
                opcode = RC.ACKNOWLEDGE,
                psn = req[BTH].psn,
                dqpn = self.dqpn(),
            )
            rnr_nak_aeth = AETH(code = 'RNR', value = rnr_wait_timer, msn = self.msn)
            rnr_nak = rnr_nak_bth/rnr_nak_aeth
            self.send_pkt(rnr_nak)
            self.rnr_nak_wait_clear_ts_ns = cur_ts_ns + Util.rnr_timer_to_ns(rnr_wait_timer) # The timestamp RNR NAK wait timer to be cleared
        else:
            logging.info(f'RQ={self.sqpn()} already responsed a RNR NAK and its wait timer is not cleared, no RNR NAK to response again')

    def process_nak_seq_err(self):
        if self.nak_seq_err_clear:
            seq_nak_bth = BTH(
                opcode = RC.ACKNOWLEDGE,
                psn = self.rq_psn,
                dqpn = self.dqpn(),
            )
            seq_nak_aeth = AETH(code = 'NAK', value = 0, msn = self.msn)
            seq_nak = seq_nak_bth/seq_nak_aeth
            self.send_pkt(seq_nak)
            self.nak_seq_err_clear = False # There is a NAK seq err needs to be cleared
        else:
            logging.info(f'RQ={self.sqpn()} already responsed a NAK sequence error, and now it can only response to request matches its ePSN')

    def process_nak_err(self, req, err_wc_status, nak_wr = None):
        nak_err_bth = BTH(
            opcode = RC.ACKNOWLEDGE,
            psn = req[BTH].psn,
            dqpn = self.dqpn(),
        )
        nak_err_value = RSRV_AETH_NAK_VAL
        if err_wc_status == WC_STATUS.REM_INV_REQ_ERR:
            nak_err_value = 1
            logging.error(f'RQ={self.sqpn()} sent NAK remote invalid request error')
        elif err_wc_status == WC_STATUS.REM_ACCESS_ERR:
            nak_err_value = 2
            logging.error(f'RQ={self.sqpn()} sent NAK remote access error')
        elif err_wc_status == WC_STATUS.REM_OP_ERR:
            nak_err_value = 3
            logging.error(f'RQ={self.sqpn()} sent NAK remote operation error')
        else:
            assert err_wc_status in [
                WC_STATUS.REM_INV_REQ_ERR,
                WC_STATUS.REM_ACCESS_ERR,
                WC_STATUS.REM_OP_ERR,
            ], 'NAK error should be REM_INV_REQ_ERR, REM_ACCESS_ERR, REM_OP_ERR'
        nak_err_aeth = AETH(code = 'NAK', value = nak_err_value, msn = self.msn)
        nak_err = nak_err_bth/nak_err_aeth
        self.send_pkt(nak_err)
        self.goto_err_state(req[BTH].opcode, err_wc_status, nak_wr = nak_wr)

    def goto_err_state(self, rc_op, err_wc_status, nak_wr = None):
        self.qp.modify_qp(qps = QPS.ERR)
        if nak_wr is not None:
            # Explicit NAK corresponding request
            nak_cqe = CQE(
                wr_id = nak_sr.id(),
                status = err_wc_status,
                opcode = WC_OPCODE.from_rc_op(rc_op),
                length = nak_sr.len(),
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = EMPTY_WC_FLAG,
            )
            self.cq.push(nak_cqe)
        else:
            self.qp.add_async_event(EVENT_TYPE.from_wc_status(err_wc_status))
        self.qp.flush()
        # Since RQ is single threaded, so no other incoming request/response pending

class QP:
    def __init__(self, pd, cq, qpn, pmtu, access_flags, use_ipv6,
        rq_psn = 0,
        sq_psn = 0,
        pkey = DEFAULT_PKEY,
        sq_draining = 0,
        max_rd_atomic = 10,
        max_dest_rd_atomic = 10,
        min_rnr_timer = 10,
        timeout = 10,
        retry_cnt = 3,
        rnr_retry = 3,
    ):
        self.pd = pd # TODO: check pd match for each req
        self.cq = cq
        self.qps = QPS.INIT
        self.qp_num = qpn
        self.event_queue = []

        self.pmtu = pmtu
        self.dst_gid = None
        self.dst_qpn = None
        self.access_flags = access_flags
        self.partition_key = pkey
        self.max_rd_atomic = max_rd_atomic
        self.max_dest_rd_atomic = max_dest_rd_atomic
        self.min_rnr_timer = min_rnr_timer
        self.timeout = timeout
        self.retry_cnt = retry_cnt
        self.rnr_retry = rnr_retry

        self.use_ipv6 = use_ipv6

        self.sq = SQ(
            qp = self,
            cq = cq,
            sq_psn = sq_psn,
            sq_draining = sq_draining,
        )
        self.rq = RQ(
            qp = self,
            cq = cq,
            rq_psn = rq_psn,
        )
        self.soc = SendOutstandingContext(qp = self)
        self.pd.add_qp(self)

    def modify_qp(self,
        qps = None,
        pmtu = None,
        rq_psn = None,
        sq_psn = None,
        dgid = None,
        dst_qpn = None,
        access_flags = None,
        pkey = None,
        sq_draining = None,
        max_rd_atomic = None,
        max_dest_rd_atomic = None,
        min_rnr_timer = None,
        timeout = None,
        retry_cnt = None,
        rnr_retry = None,
    ):
        if qps is not None:
            self.qps = qps
        if pmtu is not None:
            self.pmtu = pmtu
        if dgid is not None:
            self.dst_gid = dgid
        if dst_qpn is not None:
            self.dst_qpn = dst_qpn
        if access_flags is not None:
            self.access_flags = access_flags
        if pkey is not None:
            self.partition_key = pkey
        if max_rd_atomic is not None:
            self.max_rd_atomic = max_rd_atomic
        if max_dest_rd_atomic is not None:
            self.max_dest_rd_atomic = max_dest_rd_atomic
        if min_rnr_timer is not None:
            self.min_rnr_timer = min_rnr_timer
        if timeout is not None:
            self.timeout = timeout
        if retry_cnt is not None:
            self.retry_cnt = retry_cnt
        if rnr_retry is not None:
            self.rnr_retry = rnr_retry

        self.sq.modify(sq_psn = sq_psn, sq_draining = sq_draining)
        self.rq.modify(rq_psn = rq_psn)
        self.soc.modify(sq_psn = sq_psn)

    def qpn(self):
        return self.qp_num

    def dqpn(self):
        return self.dst_qpn

    def dgid(self):
        return self.dst_gid

    def pkey(self):
        return self.partition_key

    def flags(self):
        return self.access_flags

    def mtu(self):
        return self.pmtu

    def recv_pkt(self, pkt, retry_handler):
        assert self.qps in [QPS.RTS, QPS.RTR], 'QP state is not RTS or RTR'
        self.rq.recv_pkt(pkt, retry_handler)

    def poll_cq(self):
        if not self.cq.empty():
            return self.cq.pop()
        else:
            return None

    def post_send(self, send_wr):
        assert self.qps == QPS.RTS, 'QP state is not RTS'
        self.sq.push(send_wr)

    def post_recv(self, recv_wr):
        assert self.qps in [QPS.RTS, QPS.RTR], 'QP state is not RTS or RTR'
        self.rq.push(recv_wr)

    def process_one_sr(self):
        assert self.qps == QPS.RTS, 'QP state is not RTS'

        check_res, err_psn = self.soc.check_timeout_and_retry() # Check request timeout and retry if any
        if check_res != WC_STATUS.SUCCESS:
            logging.error(f'SQ={self.qpn()} local detected: timeout retry error')
            return self.soc.goto_err_state(err_psn, check_res)

        if not self.soc.full():
            wr, cssn = self.sq.pop()
            self.soc.add_wr(wr, cssn) # Add WR to SendOutstandingContext first, before send packets

            if WR_OPCODE.send(wr.op()):
                self.sq.process_send_req(wr, cssn)
            elif WR_OPCODE.write(wr.op()):
                self.sq.process_write_req(wr, cssn)
            elif WR_OPCODE.RDMA_READ == wr.opcode:
                self.sq.process_read_req(wr, cssn)
            elif WR_OPCODE.atomic(wr.op()):
                self.sq.process_atomic_req(wr, cssn)
            else:
                raise Exception(f'SQ={self.qpn()} met unsupported opcode: {wr.opcode}')

            return True
        else:
            logging.debug(f'SQ={self.qpn()} has sent too many requests, {self.soc.pending_rd_atomic_wr_num} outstanding read/atomic requests')
            return False

    def flush(self): # Flush all WR in SQ/RQ
        while not (self.sq.empty() and self.rq.empty()):
            flush_sr = self.sq.pop() if not self.sq.empty() else self.rq.pop()
            flush_cqe = CQE(
                wr_id = flush_sr.id(),
                status = WC_STATUS.WR_FLUSH_ERR,
                opcode = WC_OPCODE.from_wr_op(flush_sr.id()),
                length = flush_sr.len(),
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = EMPTY_WC_FLAG,
            )
            self.cq.push(flush_cqe)

    def add_async_event(self, event_type):
        self.event_queue.append(event_type)

    def get_async_event(self):
        TODO

class RoCEv2:
    def __init__(self, pmtu = PMTU.MTU_256, use_ipv6 = False, recv_timeout_secs = 1):
        self.roce_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        roce_bind_addr = ('0.0.0.0', ROCE_PORT)
        self.roce_sock.bind(roce_bind_addr)
        self.pmtu = pmtu
        self.use_ipv6 = use_ipv6
        self.recv_timeout_secs = recv_timeout_secs
        self.cur_cqn = 0
        self.cur_pdn = 0
        self.cur_qpn = 2
        self.cq_dict = {}
        self.pd_dict = {}
        self.qp_dict = {}

    def alloc_pd(self):
        pdn = self.cur_pdn
        self.cur_pdn += 1
        pd = PD(pdn)
        self.pd_dict[pdn] = pd
        return pd

    def create_cq(self):
        cqn = self.cur_cqn
        self.cur_cqn += 1
        cq = CQ(cqn)
        self.cq_dict[cqn] = cq
        return cq

    def create_qp(self, pd, cq, access_flags):
        qpn = self.cur_qpn
        self.cur_qpn += 1
        qp = QP(pd = pd, cq = cq, qpn = qpn, access_flags = access_flags, pmtu = self.pmtu, use_ipv6 = self.use_ipv6)
        self.qp_dict[qpn] = qp
        return qp

    def mtu(self):
        return self.pmtu

    def recv_pkts(self, npkt = 1, retry_handler = None):
        for i in range(npkt):
            # TODO: handle receive timeout retry
            self.roce_sock.settimeout(self.recv_timeout_secs)
            roce_bytes, peer_addr = self.roce_sock.recvfrom(UDP_BUF_SIZE)
            # TODO: handle wrong RoCE packet
            roce_pkt = BTH(roce_bytes)
            # TODO: handle head verification, wrong QPN
            local_qp = self.qp_dict[roce_pkt.dqpn]
            local_qp.recv_pkt(roce_pkt, retry_handler)
        logging.debug(f'received {npkt} RoCE packets')
