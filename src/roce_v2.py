import logging
import random
import socket
import struct
import sys

# from logging import debug, info, warning, error, critical
from roce_enum import *
from scapy.all import *
from roce import *

ROCE_PORT = 4791
UDP_BUF_SIZE = 1024
PKEY_DEFAULT = 0xFFFF
CREDIT_CNT_INVALID = 31
ATOMIC_BYTE_SIZE = 8

MAX_SSN = 2**24
MAX_MSN = 2**24
MAX_PSN = 2**24


class Util:
    def check_pkt_size(mtu, pkt):
        op = pkt[BTH].opcode
        # TODO: check why packet raw data length is 240 not 256?
        if RC.first_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_FIRST:
            #print(f'len(pkt[Raw].load)={len(pkt[Raw].load)}')
            assert len(pkt[Raw].load) == mtu
        elif RC.mid_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_MIDDLE:
            #print(f'len(pkt[Raw].load)={len(pkt[Raw].load)}')
            assert len(pkt[Raw].load) == mtu
        elif RC.last_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_LAST:
            #print(f'len(pkt[Raw].load)={len(pkt[Raw].load)}')
            assert len(pkt[Raw].load) <= mtu and len(pkt[Raw].load) > 0
        elif RC.only_req_pkt(op) or op == RC.RDMA_READ_RESPONSE_ONLY:
            if pkt.haslayer(Raw):
                #print(f'len(pkt[Raw].load)={len(pkt[Raw].load)}')
                assert len(pkt[Raw].load) <= mtu
        return True

    def check_pre_cur_ops(pre_op, cur_op):
        if pre_op == RC.SEND_FIRST or pre_op == RC.SEND_MIDDLE:
            assert cur_op == RC.SEND_MIDDLE or RC.send_last(cur_op)
        elif pre_op == RC.RDMA_WRITE_FIRST or pre_op == RC.RDMA_WRITE_MIDDLE:
            assert cur_op == RC.RDMA_WRITE_MIDDLE or RC.write_last(cur_op)
        elif pre_op == RC.RDMA_READ_RESPONSE_FIRST or pre_op == RC.RDMA_READ_RESPONSE_MIDDLE:
            assert cur_op == RC.RDMA_READ_RESPONSE_MIDDLE or cur_op == RC.RDMA_READ_RESPONSE_LAST
        elif (RC.last_req_pkt(pre_op) or RC.only_req_pkt(pre_op) or RC.atomic(pre_op)
                or pre_op == RC.RDMA_READ_RESPONSE_LAST or pre_op == RC.RDMA_READ_RESPONSE_ONLY):
            assert not (RC.mid_req_pkt(cur_op) or RC.last_req_pkt(cur_op)
                        or cur_op == RC.RDMA_READ_RESPONSE_MIDDLE or cur_op == RC.RDMA_READ_RESPONSE_LAST)

        return True

    def check_op_perm_for_qp(op, access_flags):
        # TODO: check op permission w.r.t. access flags
        return True

    def check_addr_aligned(addr, mr):
        addr_in_mr = addr
        if ACCESS_FLAGS.ZERO_BASED & mr.flags():
            addr_in_mr = mr.addr() + addr
        assert addr_in_mr >= mr.addr() and addr_in_mr <= mr.addr() + mr.len(), f'address={addr} is not within MR'
        # TODO: handle non-aligned address error
        assert addr_in_mr == ((addr_in_mr >> 3) << 3)

        return True

class MR:
    def __init__(self, va, length, access_flags, lkey, rkey):
        assert ACCESS_FLAGS.ZERO_BASED & access_flags, 'only zero-based address supported'
        self.va = va
        self.local_key = lkey
        self.remote_key = rkey
        self.length = length
        self.access_flags = access_flags
        self.byte_data = bytearray(struct.pack(f'<{self.len()}s', b''))
        self.pos = 0
        self.write_append_size = 0

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

    def write(self, byte_data, pos = 0):
        assert pos + len(byte_data) <= self.len(), 'write overrun'
        self.byte_data[pos : (pos + len(byte_data))] = byte_data
        self.write_append_size = len(byte_data)
        self.pos = pos + len(byte_data)

    def append(self, byte_data):
        assert self.pos + len(byte_data) <= self.len()
        self.byte_data[self.pos : (self.pos + len(byte_data))] = byte_data
        self.write_append_size += len(byte_data)
        self.pos += len(byte_data)

    def read_all(self):
        assert len(self.byte_data) == self.len()
        return self.byte_data

    def write_and_append_size(self):
        return self.write_append_size

class PD:
    def __init__(self, pdn):
        self.pdn = pdn
        self.qp_dict = {}
        #self.cq_dict = {}
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
        send_flags = DEFAULT_FLAG,
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

class SQ:
    def __init__(self, pd, cq, qpn, sq_psn, pmtu, access_flags, use_ipv6,
        pkey = PKEY_DEFAULT,
        draining = 0,
        max_rd_atomic = 10,
        max_dest_rd_atomic = 10,
        min_rnr_timer = 10,
        timeout = 10,
        retry_cnt = 3,
        rnr_rery = 3,
    ):
        self.sq = []
        self.qps = QPS.INIT
        self.pd = pd # TODO: check pd match for each req
        self.cq = cq
        self.qpn = qpn
        self.sq_psn = sq_psn % MAX_PSN
        self.pmtu = pmtu
        self.ssn = 1
        self.draining = draining

        self.dgid = None
        self.dst_qpn = None
        self.access_flags = access_flags
        self.pkey = pkey
        self.draining = draining
        self.max_rd_atomic = max_rd_atomic
        self.max_dest_rd_atomic = max_dest_rd_atomic
        self.min_rnr_timer = min_rnr_timer
        self.timeout = timeout
        self.retry_cnt = retry_cnt
        self.rnr_rery = rnr_rery

        self.use_ipv6 = use_ipv6
        self.req_pkt_dict = {}
        self.sent_wr_dict = {}
        self.oldest_psn = sq_psn
        self.min_unacked_psn = sq_psn

    def modify(self,
        qps = None,
        pmtu = None,
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
        rnr_rery = None,
    ):
        if qps:
            self.qps = qps
        if pmtu:
            self.pmtu = pmtu
        if sq_psn:
            self.sq_psn = sq_psn % MAX_PSN
        if dgid:
            self.dgid = dgid
        if dst_qpn:
            self.dst_qpn = dst_qpn # qpn in number instread of hex string
        if access_flags:
            self.access_flags = access_flags
        if pkey:
            self.pkey = pkey
        if sq_draining:
            self.sq_draining = sq_draining
        if max_rd_atomic:
            self.max_rd_atomic = max_rd_atomic
        if max_dest_rd_atomic:
            self.max_dest_rd_atomic = max_dest_rd_atomic
        if min_rnr_timer:
            self.min_rnr_timer = min_rnr_timer
        if timeout:
            self.timeout = timeout
        if retry_cnt:
            self.retry_cnt = retry_cnt
        if rnr_rery:
            self.rnr_rery = rnr_rery

    def push(self, wr):
        wr_op = wr.op()
        # TODO: handle invalid request, access flags match
        assert WR_OPCODE.send(wr_op) or WR_OPCODE.write(wr_op) or WR_OPCODE.atomic(wr_op) or wr_op == WR_OPCODE.RDMA_READ, 'send WR has unspported opcode'
        # TODO: handle immediate errors
        if wr.op() in [WR_OPCODE.SEND_WITH_IMM, WR_OPCODE.SEND_WITH_INV, WR_OPCODE.RDMA_WRITE_WITH_IMM]:
            assert wr.imm_data_or_inv_rkey(), 'send/write with immediate data or send with invalidate requires send WR has imm_data_or_inv_rkey'

        if wr.len():
            local_key = wr.lkey()
            # TODO: handle immediate error
            assert self.pd.has_mr(local_key), 'send WR has invalid lkey'
            mr = self.pd.get_mr(local_key)
            # TODO: handle immediate error
            assert wr.laddr() + wr.len() <= mr.len(), 'send WR local SG is not within its MR'
        
        self.sq.append(wr)

    def pop(self):
        sr = self.sq.pop(0)
        cssn = self.ssn
        self.sent_wr_dict[cssn] = sr
        self.ssn = (self.ssn + 1) % MAX_SSN
        return (sr, cssn)

    def empty(self):
        return not bool(self.sq)

    def sqpn(self):
        return self.qpn

    def dqpn(self):
        return self.dst_qpn

    def get_qp_access_flags(self):
        return self.access_flags

    def check_sq_psn(self, psn):
        # TODO: consider PSN comparison w.r.t. MAX_PSN
        if psn < self.min_unacked_psn:
            # TODO: handle dup response
            return False
        elif psn >= self.sq_psn:
            # This case should never happen according to IBA spec
            return False
        else:
            return True

    def process_one(self):
        if not self.dqpn():
            raise Exception(f'QP={self.sqpn()} has no destination QPN')
        elif not self.dgid:
            raise Exception(f'QP={self.sqpn()} has no destination GID')

        sr, cssn = self.pop()
        if WR_OPCODE.send(sr.op()):
            self.process_send_req(sr, cssn)
        elif WR_OPCODE.write(sr.op()):
            self.process_write_req(sr, cssn)
        elif WR_OPCODE.RDMA_READ == sr.opcode:
            self.process_read_req(sr, cssn)
        elif WR_OPCODE.atomic(sr.op()):
            self.process_atomic_req(sr, cssn)
        else:
            raise Exception(f'unsupported opcode: {sr.opcode}')

    def send_pkt(self, cssn, req):
        cpsn = req[BTH].psn
        self.req_pkt_dict[cpsn] = (req, cssn)

        # ip_hex = socket.inet_aton('192.168.122.190').hex()
        # dst_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(self.dgid))
        dst_ipv6 = socket.inet_ntop(socket.AF_INET6, self.dgid)
        dst_ipv4 = dst_ipv6.replace('::ffff:', '')
        dst_ip = dst_ipv6 if self.use_ipv6 else dst_ipv4
        logging.debug(f'dest IP={dst_ip}')

        pkt = IP(dst=dst_ip)/UDP(dport=ROCE_PORT, sport=self.sqpn())/req
        logging.debug(f'QP={self.sqpn()} request: ' + pkt.show(dump = True))
        send(pkt)

    def process_send_req(self, sr, cssn):
        assert WR_OPCODE.send(sr.op()), 'should be send operation'
        addr = sr.laddr()
        send_size = sr.len()
        send_data = b''
        if send_size:
            mr = self.pd.get_mr(sr.lkey())
            send_data = mr.read_all()[addr : addr + send_size]

        send_req_pkt_num = math.ceil(sr.len() / self.pmtu) if send_size > 0 else 1
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
            send_req = send_bth/Raw(load = send_data[0 : self.pmtu])
            self.send_pkt(cssn, send_req)

            send_req_mid_pkt_num = send_req_pkt_num - 2
            for i in range(send_req_mid_pkt_num):
                send_bth = BTH(
                    opcode = RC.SEND_MIDDLE,
                    psn = cpsn + i + 1,
                    dqpn = dqpn,
                    ackreq = False,
                    solicited = False,
                )
                send_req = send_bth/Raw(load = send_data[((i + 1) * self.pmtu) : ((i + 2) * self.pmtu)])
                self.send_pkt(cssn, send_req)

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
            raw_pkt = Raw(load = send_data[((send_req_pkt_num - 1) * self.pmtu) : send_size])
            send_req = send_req/raw_pkt
        self.send_pkt(cssn, send_req)
        self.sq_psn = (self.sq_psn + send_req_pkt_num) % MAX_PSN

    def process_write_req(self, sr, cssn):
        assert WR_OPCODE.write(sr.op()), 'should be write operation'
        addr = sr.laddr()
        write_size = sr.len()
        write_data = b''
        if write_size:
            mr = self.pd.get_mr(sr.lkey())
            write_data = mr.read_all()[addr : addr + write_size]

        write_req_pkt_num = math.ceil(write_size / self.pmtu) if write_size else 1
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
            write_req = write_bth/write_reth/Raw(load = write_data[0 : self.pmtu])
            self.send_pkt(cssn, write_req)

            write_req_mid_pkt_num = write_req_pkt_num - 2
            for i in range(write_req_mid_pkt_num):
                write_bth = BTH(
                    opcode = RC.RDMA_WRITE_MIDDLE,
                    psn = cpsn + i + 1,
                    dqpn = dqpn,
                    ackreq = False,
                    solicited = False,
                )
                write_req = write_bth/Raw(load = write_data[((i + 1) * self.pmtu) : ((i + 2) * self.pmtu)])
                self.send_pkt(cssn, write_req)

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
            write_req = write_bth/write_reth
        else:
            write_req = write_bth
        if RC.has_imm(rc_op):
            #imm_data = ImmDt(data = sr.imm_data_or_inv_rkey())
            #write_req = write_req/imm_data
            reth_imm_data = RETHImmDt(va = sr.raddr(), rkey = sr.rkey(), dlen = write_size, data = sr.imm_data_or_inv_rkey())
            write_req = write_bth/reth_imm_data
        if write_size > 0:
            raw_pkt = Raw(load = write_data[((write_req_pkt_num - 1) * self.pmtu) : write_size])
            write_req = write_req/raw_pkt
        self.send_pkt(cssn, write_req)
        self.sq_psn = (self.sq_psn + write_req_pkt_num) % MAX_PSN

    def process_read_req(self, sr, cssn):
        assert sr.op() == WR_OPCODE.RDMA_READ, 'should be read operation'
        # TODO: handle local access permission error
        assert ACCESS_FLAGS.LOCAL_WRITE & self.get_qp_access_flags(), 'read op should have write permission to local MR'

        read_size = sr.len()
        read_resp_pkt_num = math.ceil(read_size / self.pmtu)
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
        self.send_pkt(cssn, read_req)

        # TODO: improve how to link read response PSN with read request
        for rrpsn in range(self.sq_psn, self.sq_psn + read_resp_pkt_num):
            read_resp_psn = rrpsn % MAX_PSN
            self.req_pkt_dict[rrpsn] = (read_req, cssn)
        self.sq_psn = (self.sq_psn + read_resp_pkt_num) % MAX_PSN

    def process_atomic_req(self, sr, cssn):
        assert WR_OPCODE.atomic(sr.op()), 'should be atomic operation'
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
        self.send_pkt(cssn, atomic_req)
        self.sq_psn = (self.sq_psn + 1) % MAX_PSN

    def handle_response(self, resp):
        assert resp[BTH].dqpn == self.qpn, 'QPN not match with Ack packet'
        assert self.check_sq_psn(resp[BTH].psn), 'invalid ack PSN' # TODO: should discard silently?
        assert self.min_unacked_psn < self.sq_psn, 'min unacked PSN not < SQ PSN'
        assert self.oldest_psn <= self.min_unacked_psn, 'oldest PSN not < min unacked PSN'

        # TODO: handle duplicated request and packet loss
        assert self.check_sq_psn(resp[BTH].psn), 'received duplicated packet or detected packet loss'

        rc_op = resp[BTH].opcode
        if RC.read_resp(rc_op):
            self.handle_read_resp(resp)
        elif rc_op == RC.ATOMIC_ACKNOWLEDGE:
            self.handle_atomic_ack(resp)
        elif rc_op == RC.ACKNOWLEDGE:
            self.handle_ack(resp)
        else:
            raise Exception(f'unsupported response opcode={rc_op}')

        # TODO: for multiple read response, it's better to ack after received the last read response
        self.min_unacked_psn = (resp[BTH].psn + 1) % MAX_PSN
        logging.debug(f'min unacked psn={self.min_unacked_psn}, next psn={self.sq_psn}')

    def handle_ack(self, ack):
        assert ack[BTH].opcode == RC.ACKNOWLEDGE, 'should be ack'
        # TODO: handle NAK
        assert ack[AETH].code == 0, 'ack is NAK'

        for unacked_psn in range(self.min_unacked_psn, ack.psn + 1):
            unacked_pkt, ssn = self.req_pkt_dict[unacked_psn]
            rc_op = unacked_pkt[BTH].opcode
            # Implicitly ack previous send and write operations
            if RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
                sr = self.sent_wr_dict[ssn]
                # Generate CQE for each implicitly acked send or write WR
                cqe = CQE(
                    wr_id = sr.id(),
                    status = WC_STATUS.SUCCESS,
                    opcode = RC.wc_op(rc_op),
                    length = sr.len(),
                    qpn = self.sqpn(),
                    src_qp = self.dqpn(),
                    wc_flags = 0, # Request side CQE no need to handle IBV_WC_WITH_IMM or IBV_WC_WITH_INV
                )
                # No need to retire top RQ element since this is request side, no RQ logic involved
                self.cq.push(cqe)
                # Delete completed send WR, TODO: delete acked request packets
                del self.sent_wr_dict[ssn]
            # Implicitly un-ack read and atomic operations
            assert unacked_pkt[BTH].opcode not in [
                RC.RDMA_READ_REQUEST,
                RC.COMPARE_SWAP,
                RC.FETCH_ADD,
            ], 'atomic or read request not acked' # TODO: handle NAK retry atomic req

    def handle_read_resp(self, read_resp):
        rc_op = read_resp[BTH].opcode
        assert RC.read_resp(rc_op), 'should be read response'
        # TODO: handle invalid request, packet size illegal
        assert Util.check_pkt_size(self.pmtu, read_resp), 'received packet size illegal'
        # TODO: handle invalid request, access flags match
        assert Util.check_op_perm_for_qp(rc_op, self.access_flags), 'received packet has opcode without proper permission'

        read_req, ssn = self.req_pkt_dict[read_resp[BTH].psn]
        read_wr = self.sent_wr_dict[ssn]
        mr = self.pd.get_mr(read_wr.lkey())
        addr = read_wr.laddr()

        if rc_op == RC.RDMA_READ_RESPONSE_FIRST:
            mr.write(byte_data = read_resp[Raw].load, pos = addr)
        elif rc_op == RC.RDMA_READ_RESPONSE_ONLY:
            if read_resp[RETH].dlen > 0: # Handle empty read response
                mr.write(byte_data = read_resp[Raw].load, pos = addr)
        else:
            mr.append(read_resp[Raw].load)

        if rc_op == RC.RDMA_READ_RESPONSE_LAST or rc_op == RC.RDMA_READ_RESPONSE_ONLY:
            # Generate CQE for read response
            cqe_length = 0 if rc_op == RC.RDMA_READ_RESPONSE_ONLY and not Raw in read_resp else mr.write_and_append_size()
            cqe = CQE(
                wr_id = read_wr.id(),
                status = WC_STATUS.SUCCESS,
                opcode = RC.wc_op(rc_op),
                length = cqe_length,
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = 0
            )
            # No need to retire top RQ element since this is request side, no RQ logic involved
            self.cq.push(cqe)
            # Delete completed read WR
            del self.sent_wr_dict[ssn]

    def handle_atomic_ack(self, atomic_ack):
        rc_op = atomic_ack[BTH].opcode
        assert rc_op == RC.ATOMIC_ACKNOWLEDGE, 'should be atomic ack'
        # TODO: handle NAK
        assert atomic_ack[AETH].code == 0, 'atomic ack is NAK'

        atomic_req, ssn = self.req_pkt_dict[atomic_ack[BTH].psn]
        atomic_wr = self.sent_wr_dict[ssn]
        addr = atomic_wr.laddr()
        local_key = atomic_wr.lkey()
        assert self.pd.has_mr(local_key), 'should never happen'
        mr = self.pd.get_mr(local_key)
        mr.write(byte_data = atomic_ack[AtomicAckETH].orig, pos = addr)
        cqe = CQE(
            wr_id = atomic_wr.id(),
            status = WC_STATUS.SUCCESS,
            opcode = RC.wc_op(rc_op),
            length = mr.write_and_append_size(),
            qpn = self.sqpn(),
            src_qp = self.dqpn(),
            wc_flags = 0
        )
        assert mr.write_and_append_size() == ATOMIC_BYTE_SIZE, 'atomic original data should be 64 bits'
        # No need to retire top RQ element since this is request side, no RQ logic involved
        self.cq.push(cqe)
        # Delete completed atomic WR
        del self.sent_wr_dict[ssn]

class RQ:
    def __init__(self, pd, cq, sq, qpn, rq_psn, pmtu, access_flags, use_ipv6,
        pkey = PKEY_DEFAULT,
        max_rd_atomic = 10,
        max_dest_rd_atomic = 10,
        min_rnr_timer = 10,
        timeout = 10,
        retry_cnt = 3,
        rnr_rery = 3,
    ):
        self.rq = []
        self.qps = QPS.INIT
        self.pd = pd # TODO: check pd match for each req
        self.cq = cq
        self.sq = sq
        self.qpn = qpn
        self.rq_psn = rq_psn % MAX_PSN
        self.pmtu = pmtu
        self.msn = 0

        self.dgid = None
        self.dst_qpn = None
        self.access_flags = access_flags
        self.pkey = pkey
        self.max_rd_atomic = max_rd_atomic
        self.max_dest_rd_atomic = max_dest_rd_atomic
        self.min_rnr_timer = min_rnr_timer
        self.timeout = timeout
        self.retry_cnt = retry_cnt
        self.rnr_rery = rnr_rery

        self.use_ipv6 = use_ipv6
        self.resp_pkt_dict = {}
        self.pre_pkt_op = None
        self.cur_write_mr = None

    def modify(self,
        qps = None,
        pmtu = None,
        rq_psn = None,
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
        rnr_rery = None,
    ):
        if qps:
            self.qps = qps
        if pmtu:
            self.pmtu = pmtu
        if rq_psn:
            self.rq_psn = rq_psn % MAX_PSN
        if dgid:
            self.dgid = dgid
        if dst_qpn:
            self.dst_qpn = dst_qpn # qpn in number instread of hex string
        if access_flags:
            self.access_flags = access_flags
        if pkey:
            self.pkey = pkey
        if sq_draining:
            self.sq_draining = sq_draining
        if max_rd_atomic:
            self.max_rd_atomic = max_rd_atomic
        if max_dest_rd_atomic:
            self.max_dest_rd_atomic = max_dest_rd_atomic
        if min_rnr_timer:
            self.min_rnr_timer = min_rnr_timer
        if timeout:
            self.timeout = timeout
        if retry_cnt:
            self.retry_cnt = retry_cnt
        if rnr_rery:
            self.rnr_rery = rnr_rery

    def push(self, wr):
        self.rq.append(wr)

    def pop(self):
        return self.rq.pop(0)

    def top(self):
        return self.rq[0]

    def empty(self):
        return not bool(self.rq)

    def sqpn(self):
        return self.qpn

    def dqpn(self):
        return self.dst_qpn

    def get_qp_access_flags(self):
        return self.access_flags

    def check_rq_psn(self, psn):
        # TODO: consider PSN comparison w.r.t. MAX_PSN
        if psn < self.rq_psn:
            # TODO: handle dup request, whether ackreq=1 needed?
            return False
        else:
            # TODO: handle packet loss, e.g. pkt.psn > self.rq_psn
            assert psn == self.rq_psn, 'ePSN not match received PSN'
            return True

    def send_pkt(self, resp):
        if not self.dqpn():
            raise Exception(f'QP={self.sqpn()} has no destination QPN')
        elif not self.dgid:
            raise Exception(f'QP={self.sqpn()} has no destination GID')

        #dst_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(self.dgid))
        dst_ipv6 = socket.inet_ntop(socket.AF_INET6, self.dgid)
        dst_ipv4 = dst_ipv6.replace('::ffff:', '')
        dst_ip = dst_ipv6 if self.use_ipv6 else dst_ipv4
        logging.debug(f'dest IP={dst_ip}')

        pkt = IP(dst=dst_ip)/UDP(dport=ROCE_PORT, sport=self.sqpn())/resp
        cpsn = pkt[BTH].psn
        self.resp_pkt_dict[cpsn] = pkt
        logging.debug(f'QP={self.sqpn()} response: ' + pkt.show(dump = True))
        send(pkt)

    def recv_pkt(self, pkt):
        logging.debug(f'QP={self.sqpn()} received packet with length={len(pkt)}：' + pkt.show(dump = True))
        rc_op = pkt[BTH].opcode

        assert pkt.dqpn == self.qpn, 'received packet QPN not match'
        # TODO: handle invalid request
        assert Util.check_pre_cur_ops(self.pre_pkt_op, rc_op), 'previous and current opcodes are not legal'

        if RC.request(rc_op):
            # TODO: handle invalid request, packet size illegal
            assert Util.check_pkt_size(self.pmtu, pkt), 'received packet size illegal'
            # TODO: handle invalid request, access flags match
            assert Util.check_op_perm_for_qp(rc_op, self.access_flags), 'received packet has opcode without proper permission'
            # TODO: handle duplicated request and packet loss
            assert self.check_rq_psn(pkt[BTH].psn), 'received duplicated packet or detected packet loss'
            # TODO: handle sequence error
            assert self.rq_psn == pkt[BTH].psn, 'request PSN not match'

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
        elif RC.response(rc_op):
            self.sq.handle_response(pkt)
        else:
            raise Exception(f'unsupported opcode={rc_op}')
        self.pre_pkt_op = rc_op

    def handle_send_req(self, send_req):
        rc_op = send_req[BTH].opcode
        assert RC.send(rc_op), 'should be send request'
        # TODO: handle rnr
        assert not self.empty(), 'RQ empty'

        rr = self.top()
        assert self.pd.has_mr(rr.lkey()), 'invalid lkey in receive wr'
        mr = self.pd.get_mr(rr.lkey())
        # TODO: handle local access permission error
        assert ACCESS_FLAGS.LOCAL_WRITE & mr.flags(), 'send request needs receive WR has local write permission'
        addr = rr.addr()
        if RC.first_req_pkt(rc_op):
            mr.write(send_req[Raw].load, pos = addr)
        elif RC.only_req_pkt(rc_op):
            if Raw in send_req: # Handle empty send request, that no Raw layer
                mr.write(send_req[Raw].load, pos = addr)
        else:
            mr.append(send_req[Raw].load)

        if RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            self.pop()
            self.msn = (self.msn + 1) % MAX_MSN

            cqe_wc_flags = 0
            cqe_imm_data_or_inv_rkey = None
            if RC.has_imm(rc_op):
                cqe_wc_flags |= WC_FLAGS.WITH_IMM
                cqe_imm_data_or_inv_rkey = send_req[ImmDt].data
            elif RC.has_inv(rc_op):
                cqe_wc_flags |= WC_FLAGS.WITH_INV
                cqe_imm_data_or_inv_rkey = send_req[IETH].rkey # TODO: handle rkey invalidation
            cqe_length = 0 if RC.only_req_pkt(rc_op) and not Raw in send_req else mr.write_and_append_size()
            # Generate CQE for received send request
            cqe = CQE(
                wr_id = rr.id(),
                status = WC_STATUS.SUCCESS,
                opcode = RC.wc_op(rc_op),
                length = cqe_length,
                qpn = self.sqpn(),
                src_qp = self.dqpn(),
                wc_flags = cqe_wc_flags,
                imm_data_or_inv_rkey = cqe_imm_data_or_inv_rkey,
            )
            self.cq.push(cqe)

            if send_req[BTH].solicited:
                # TODO: handle solicited event
                TODO
        self.rq_psn = (self.rq_psn + 1) % MAX_PSN # Update ePSN
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
            assert self.pd.has_mr(write_req_rkey), 'invalid rkey in write request'
            self.cur_write_mr = self.pd.get_mr(write_req_rkey)
            assert write_req_dlen <= self.cur_write_mr.len(), 'write request size larger than MR size'
            # TODO: handle local MR access permission error
            assert ACCESS_FLAGS.REMOTE_WRITE & self.cur_write_mr.flags(), 'write request needs receive MR has remote write permission'
            # TODO: handle local QP operation permission error
            assert ACCESS_FLAGS.REMOTE_WRITE & self.get_qp_access_flags(), 'write request needs receive QP has remote write permission'

        mr = self.cur_write_mr
        if RC.first_req_pkt(rc_op):
            #addr = write_req[RETH].va
            mr.write(write_req[Raw].load, pos = write_req_addr)
        elif RC.only_req_pkt(rc_op):
            if write_req_dlen > 0: # Handle empty write response
                #addr = write_req[RETH].va
                mr.write(write_req[Raw].load, pos = write_req_addr)
        else:
            mr.append(write_req[Raw].load)

        if RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            self.msn = (self.msn + 1) % MAX_MSN
            self.cur_write_mr = None # Reset cur_write_mr to None after receive the last or only write request

            if RC.has_imm(rc_op):
                cqe_wc_flags = WC_FLAGS.WITH_IMM
                cqe_imm_data = write_req[RETHImmDt].data
                # TODO: handle RQ empty when write with imm
                assert not self.empty(), 'RQ is empty but write with immediate data needs to consume a receive WR'
                rr = self.pop()
                cqe_length = write_req_dlen if RC.only_req_pkt(rc_op) else mr.write_and_append_size()
                # Generate CQE for received send request
                cqe = CQE(
                    wr_id = rr.id(),
                    status = WC_STATUS.SUCCESS,
                    opcode = RC.wc_op(rc_op),
                    length = cqe_length,
                    qpn = self.sqpn(),
                    src_qp = self.dqpn(),
                    wc_flags = cqe_wc_flags,
                    imm_data_or_inv_rkey = cqe_imm_data,
                )
                self.cq.push(cqe)

                if write_req[BTH].solicited:
                    # TODO: handle solicited event
                    TODO
        self.rq_psn = (self.rq_psn + 1) % MAX_PSN # Update ePSN
        if write_req[BTH].ackreq:
            self.process_ack(write_req)

    def handle_read_req(self, read_req):
        rc_op = read_req[BTH].opcode
        assert rc_op == RC.RDMA_READ_REQUEST, 'should be read request'

        read_size = read_req[RETH].dlen
        # TODO: handle invalid request, rkey is invalid
        assert self.pd.has_mr(read_req[RETH].rkey), 'invalid rkey in read request'
        mr = self.pd.get_mr(read_req[RETH].rkey)
        addr = read_req[RETH].va
        # TODO: handle local access permission error
        assert ACCESS_FLAGS.REMOTE_READ & mr.flags(), 'read request needs local MR has remote read permission'
        # TODO: handle local QP operation permission error
        assert ACCESS_FLAGS.REMOTE_READ & self.get_qp_access_flags(), 'read request needs receive QP has remote read permission'
        assert addr + read_size <= mr.len(), 'read request size larger than MR size'

        cpsn = self.rq_psn
        dqpn = self.dqpn()
        self.msn = (self.msn + 1) % MAX_MSN
        read_resp_pkt_num = math.ceil(read_size / self.pmtu) if read_size > 0 else 1
        read_data = mr.read_all()[addr : (addr + read_size)]
        read_aeth = AETH(code = 'ACK', value = CREDIT_CNT_INVALID, msn = self.msn)
        if read_resp_pkt_num > 1:
            read_resp_bth = BTH(
                opcode = RC.RDMA_READ_RESPONSE_FIRST,
                psn = cpsn,
                dqpn = dqpn,
            )
            read_resp = read_resp_bth/read_aeth/Raw(load = read_data[0 : self.pmtu])
            self.send_pkt(read_resp)

            read_resp_mid_pkt_num = read_resp_pkt_num - 2
            for i in range(read_resp_mid_pkt_num):
                read_resp_bth = BTH(
                    opcode = RC.RDMA_READ_RESPONSE_MIDDLE,
                    psn = cpsn + i + 1,
                    dqpn = dqpn,
                )
                read_resp = read_resp_bth/Raw(load = read_data[((i + 1) * self.pmtu) : ((i + 2) * self.pmtu)])
                self.send_pkt(read_resp)

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
        if read_size > 0:
            read_resp = read_resp/Raw(load = read_data[((read_resp_pkt_num - 1) * self.pmtu) : read_size])
        self.send_pkt(read_resp)
        self.rq_psn = (self.rq_psn + read_resp_pkt_num) % MAX_PSN

    def handle_atomic_req(self, atomic_req):
        rc_op = atomic_req[BTH].opcode
        assert RC.atomic(rc_op), 'should be atomic request'

        # TODO: handle invalid request, rkey is invalid
        assert self.pd.has_mr(atomic_req[AtomicETH].rkey), 'invalid rkey in atomic request'
        mr = self.pd.get_mr(atomic_req[AtomicETH].rkey)
        addr = atomic_req[AtomicETH].va
        # TODO: handle invalid request, MR size not enough
        assert addr + ATOMIC_BYTE_SIZE <= mr.len(), 'MR size is not enought'
        # TODO: handle local access permission error
        assert ACCESS_FLAGS.REMOTE_ATOMIC & mr.flags(), 'atomic request needs local MR has remote atomic permission'
        # TODO: handle local QP operation permission error
        assert ACCESS_FLAGS.REMOTE_ATOMIC & self.get_qp_access_flags(), 'atomic request needs receive QP has remote atomic permission'

        cpsn = self.rq_psn
        dqpn = self.dqpn()
        self.msn = (self.msn + 1) % MAX_MSN

        # TODO: handle invalid request, va is not 8-byte aligned
        assert Util.check_addr_aligned(addr = atomic_req[AtomicETH].va, mr = mr), 'atomic request address is not 8-byte aligned'
        orig = int.from_bytes(mr.read_all()[addr : (addr + ATOMIC_BYTE_SIZE)], sys.byteorder)
        comp = atomic_req[AtomicETH].comp
        swap = atomic_req[AtomicETH].swap
        if rc_op == RC.COMPARE_SWAP:
            if orig == comp:
                mr.write(byte_data = swap.to_bytes(ATOMIC_BYTE_SIZE, sys.byteorder), pos = addr)
        else:
            mr.write(byte_data = (orig + comp).to_bytes(ATOMIC_BYTE_SIZE, sys.byteorder), pos = addr)

        ack_bth = BTH(
            opcode = RC.ATOMIC_ACKNOWLEDGE,
            psn = cpsn,
            dqpn = dqpn,
        )
        ack_aeth = AETH(code = 'ACK', value = CREDIT_CNT_INVALID, msn = self.msn)
        atomic_ack_eth = AtomicAckETH(orig = orig)
        atomic_ack = ack_bth/ack_aeth/atomic_ack_eth
        self.send_pkt(atomic_ack)
        self.rq_psn = (self.rq_psn + 1) % MAX_PSN # Update ePSN

    def process_ack(self, req):
        assert req.ackreq, 'request should expect ack'
        ack_bth = BTH(
            opcode = RC.ACKNOWLEDGE,
            psn = req[BTH].psn,
            dqpn = self.dqpn(),
        )
        # TODO: RQ flow control
        ack = ack_bth/AETH(code = 'ACK', value = CREDIT_CNT_INVALID, msn = self.msn)
        self.send_pkt(ack)

class QP:
    def __init__(self, pd, cq, qpn, pmtu, access_flags, use_ipv6,
        rq_psn = 0,
        sq_psn = 0,
        pkey = PKEY_DEFAULT,
        sq_draining = 0,
        max_rd_atomic = 10,
        max_dest_rd_atomic = 10,
        min_rnr_timer = 10,
        timeout = 10,
        retry_cnt = 3,
        rnr_rery = 3,
    ):
        self.cq = cq
        self.sq = SQ(
            pd = pd,
            cq = cq,
            qpn = qpn,
            sq_psn = sq_psn,
            pmtu = pmtu,
            access_flags = access_flags,
            use_ipv6 = use_ipv6,
            pkey = pkey,
            draining = sq_draining,
            max_rd_atomic = max_rd_atomic,
            max_dest_rd_atomic = max_dest_rd_atomic,
            min_rnr_timer = min_rnr_timer,
            timeout = timeout,
            retry_cnt = retry_cnt,
            rnr_rery = rnr_rery,
        )
        self.rq = RQ(
            pd = pd,
            cq = cq,
            sq = self.sq,
            qpn = qpn,
            rq_psn = rq_psn,
            pmtu = pmtu,
            access_flags = access_flags,
            use_ipv6 = use_ipv6,
            pkey = pkey,
            max_rd_atomic = max_rd_atomic,
            max_dest_rd_atomic = max_dest_rd_atomic,
            min_rnr_timer = min_rnr_timer,
            timeout = timeout,
            retry_cnt = retry_cnt,
            rnr_rery = rnr_rery,
        )
        pd.add_qp(self)

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
        rnr_rery = None,
    ):
        self.sq.modify(
            qps = qps,
            pmtu = pmtu,
            sq_psn = sq_psn,
            dgid = dgid,
            dst_qpn = dst_qpn,
            access_flags = access_flags,
            pkey = pkey,
            sq_draining = sq_draining,
            max_rd_atomic = max_rd_atomic,
            max_dest_rd_atomic = max_dest_rd_atomic,
            min_rnr_timer = min_rnr_timer,
            timeout = timeout,
            retry_cnt = retry_cnt,
            rnr_rery = rnr_rery,
        )
        self.rq.modify(
            qps = qps,
            pmtu = pmtu,
            rq_psn = rq_psn,
            dgid = dgid,
            dst_qpn = dst_qpn,
            access_flags = access_flags,
            pkey = pkey,
            sq_draining = sq_draining,
            max_rd_atomic = max_rd_atomic,
            max_dest_rd_atomic = max_dest_rd_atomic,
            min_rnr_timer = min_rnr_timer,
            timeout = timeout,
            retry_cnt = retry_cnt,
            rnr_rery = rnr_rery,
        )

    def qpn(self):
        return self.sq.sqpn()

    def recv_pkt(self, pkt):
        self.rq.recv_pkt(pkt)

    def poll_cq(self):
        if not self.cq.empty():
            return self.cq.pop()
        else:
            return None

    def post_send(self, send_wr):
        self.sq.push(send_wr)

    def post_recv(self, recv_wr):
        self.rq.push(recv_wr)

    def process_one_sr(self):
        self.sq.process_one()

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

    def recv_pkts(self, npkt = 1):
        for i in range(npkt):
            # TODO: handle retry
            self.roce_sock.settimeout(self.recv_timeout_secs)
            roce_bytes, peer_addr = self.roce_sock.recvfrom(UDP_BUF_SIZE)
            roce_pkt = BTH(roce_bytes)
            # TODO: handle head verification, wrong QPN
            local_qp = self.qp_dict[roce_pkt.dqpn]
            local_qp.recv_pkt(roce_pkt)
        logging.debug(f'received {npkt} RoCE packets')
