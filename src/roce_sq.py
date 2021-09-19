import copy
import logging
import time

from roce import *
from roce_enum import *
from roce_util import *
from scapy.all import *


class SQLocalErrException(Exception):
    def __init__(self, send_q, err_pkt_psn, err_wc_status):
        self.send_q = send_q
        self.err_pkt_psn = err_pkt_psn
        self.err_wc_status = err_wc_status

    def process_local_err(self):
        assert self.send_q.has_psn(
            self.err_pkt_psn
        ), "resp_pkt_psn should in req_pkt_psn_wr_ssn_dict or read_resp_psn_wr_ssn_dict"
        self.send_q.goto_err_state(
            err_pkt_psn=self.err_pkt_psn,
            err_wc_status=self.err_wc_status,
        )


class SQRetryException(Exception):
    def __init__(self, send_q, psn_begin_retry, retry_type):
        self.send_q = send_q
        self.psn_begin_retry = psn_begin_retry
        self.retry_type = retry_type

    def process_retry(self):
        self.send_q.retry_logic.retry_pkts(
            psn_begin_retry=self.psn_begin_retry,
            retry_type=self.retry_type,
        ),


class SQNakErrException(Exception):
    def __init__(self, send_q, err_pkt_psn, err_wc_status):
        self.send_q = send_q
        self.err_pkt_psn = err_pkt_psn
        self.err_wc_status = err_wc_status

    def process_nak_err(self):
        self.send_q.goto_err_state(
            err_pkt_psn=self.err_pkt_psn,
            err_wc_status=self.err_wc_status,
        )


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
#         self.byte_data += sge.data()

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
    def __init__(
        self,
        opcode,
        sgl,
        wr_id=None,
        send_flags=EMPTY_SEND_FLAG,
        rmt_va=None,
        rkey=None,
        compare_add=None,
        swap=None,
        imm_data_or_inv_rkey=None,
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

    def wr_op(self):
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


class PktInfo:
    def __init__(self, pkt):
        self.pkt = pkt
        # First time sending the packet should set retry counter as 1
        self.rnr_retry_cnt = 1
        self.other_retry_cnt = 1


class WorkReqCtx:
    def __init__(self, wr):
        self.req_wr = wr
        self.wr_pkt_dict = {}
        self.first_pkt_psn = None

    def other_retry_inc(self, pkt_psn, other_retry_limit):
        assert (
            pkt_psn in self.wr_pkt_dict
        ), "other_retry_inc() error: the PSN is not for packets of this WR"
        pkt_retry_info = self.wr_pkt_dict[pkt_psn]
        if pkt_retry_info.other_retry_cnt >= other_retry_limit:
            return False
        pkt_retry_info.other_retry_cnt += 1
        return True

    def rnr_retry_inc(self, pkt_psn, rnr_retry_limit):
        assert (
            pkt_psn in self.wr_pkt_dict
        ), "rnr_retry_inc() error: the PSN is not for packets of this WR"
        pkt_retry_info = self.wr_pkt_dict[pkt_psn]
        if pkt_retry_info.rnr_retry_cnt >= rnr_retry_limit:
            return False
        pkt_retry_info.rnr_retry_cnt += 1
        return True

    def other_retry_num(self, pkt_psn):
        assert (
            pkt_psn in self.wr_pkt_dict
        ), "other_retry_num() error: the PSN is not for packets of this WR"
        pkt_retry_info = self.wr_pkt_dict[pkt_psn]
        return pkt_retry_info.other_retry_cnt

    def rnr_retry_num(self, pkt_psn):
        assert (
            pkt_psn in self.wr_pkt_dict
        ), "rnr_retry_num() error: the PSN is not for packets of this WR"
        pkt_retry_info = self.wr_pkt_dict[pkt_psn]
        return pkt_retry_info.rnr_retry_cnt

    def add_req_pkt(self, pkt):
        pkt_psn = pkt[BTH].psn
        if self.first_pkt_psn is None:
            self.first_pkt_psn = pkt_psn
        self.wr_pkt_dict[pkt_psn] = PktInfo(pkt)

    def get_req_pkt(self, pkt_psn):
        pkt_info = self.wr_pkt_dict[pkt_psn]
        return pkt_info.pkt

    def get_pkt_psn_lst(self):
        return self.wr_pkt_dict.keys()

    def pkt_num(self):
        return len(self.wr_pkt_dict)

    def first_psn(self):
        return self.first_pkt_psn

    def wr(self):
        return self.req_wr

    def laddr(self):
        return self.wr().laddr()

    def lkey(self):
        return self.wr().lkey()

    def data_size(self):
        return self.wr().len()


class RespCtx:
    def __init__(self, send_q, wr_ssn, wr, cpsn):
        self.send_q = send_q
        self.cur_psn = cpsn  # Current response PSN
        self.wr_ssn = wr_ssn
        self.pending_wr = wr
        self.req_dlen = None

    def addr(self):
        return self.wr().laddr()

    def data_size(self):
        return self.req_dlen

    def lkey(self):
        return self.pending_wr.lkey()

    def sqpn(self):
        return self.sq().sqpn()

    def dqpn(self):
        return self.sq().dqpn()

    def cpsn(self):
        return self.cur_psn

    def inc_cpsn(self):
        self.cur_psn = Util.next_psn(self.cur_psn)

    def mtu(self):
        return self.sq().qp.mtu()

    def pd(self):
        return self.sq().qp.pd

    def sq(self):
        return self.send_q

    def cq(self):
        return self.sq().cq

    def wr(self):
        return self.pending_wr

    def ssn(self):
        return self.wr_ssn


class ReadRespCtx(RespCtx):
    def __init__(self, send_q, read_wr_ssn, read_wr, read_req_pkt, read_resp_pkt_num):
        RespCtx.__init__(
            self,
            send_q=send_q,
            wr_ssn=read_wr_ssn,
            wr=read_wr,
            cpsn=read_req_pkt[BTH].psn,
        )
        self.read_mr = None
        self.cur_read_offset = 0
        self.read_req_pkt = read_req_pkt
        self.resp_pkt_psn_dict = {}

        self.req_rkey = read_req_pkt[RETH].rkey
        self.req_addr = read_req_pkt[RETH].va
        self.req_dlen = read_req_pkt[RETH].dlen

        read_req_psn = read_req_pkt[BTH].psn
        read_size = read_req_pkt[BTH].dlen
        # Save each read response PSN to read WR SSN mapping
        resp_raddr = read_req_pkt[RETH].va
        remaining_dlen = read_size
        remaining_resp_pkt_num = read_resp_pkt_num
        for read_resp_pkt_psn in Util.psn_range(
            start_psn=read_req_psn,
            end_psn=(read_req_psn + read_resp_pkt_num) % MAX_PSN,
        ):
            self.send_q.resp_logic.add_expect_read_resp_psn(
                read_resp_pkt_psn,
                read_wr_ssn,
                read_req_psn,
            )
            self.resp_pkt_psn_dict[read_resp_pkt_psn] = (
                resp_raddr,
                remaining_dlen,
                remaining_resp_pkt_num,
            )
            resp_raddr += self.mtu()
            remaining_dlen -= self.mtu()
            remaining_resp_pkt_num -= 1
        assert remaining_resp_pkt_num == 0, "remaining_resp_pkt_num should == 0"

    def get_resp_info(self, read_resp_pkt_psn):
        return self.resp_pkt_psn_dict[read_resp_pkt_psn]

    def resp_psn_lst(self):
        return self.resp_pkt_psn_dict.keys()

    def sqpn(self):
        return self.send_q.sqpn()

    def commit_resp_pkt(self, read_resp_pkt):
        rc_op = read_resp_pkt[BTH].opcode
        read_resp_psn = read_resp_pkt[BTH].psn
        assert RC.read_resp(rc_op), "should be read_response"
        if self.cpsn() != read_resp_psn:
            logging.info(
                f"SQ={self.sqpn()} read response PSN is not consecutive, \
                    expect={self.cpsn()}, actual={read_resp_psn}"
            )
            raise SQRetryException(
                send_q=self.sq(),
                psn_begin_retry=self.cpsn(),
                retry_type=RETRY_TYPE.READ_RESP_SEQ,
            )

        read_dlen = self.data_size()
        read_laddr = self.addr()
        if Raw in read_resp_pkt:
            read_lkey = self.lkey()
            read_mr = self.pd().get_mr(read_lkey)
            self.cur_read_offset += Util.write_to_mr(
                dst_mr=read_mr,
                write_to_mr_addr=read_laddr,
                data_pkt=read_resp_pkt,
            )

        if rc_op == RC.RDMA_READ_RESPONSE_LAST or rc_op == RC.RDMA_READ_RESPONSE_ONLY:
            # Handle locally detected error: Length error / Requester Class B
            if self.cur_read_offset != read_dlen:
                logging.error(
                    f"SQ={self.sqpn()} read response data size not match DMA length"
                )
                raise SQLocalErrException(
                    send_q=self.sq(),
                    err_pkt_psn=read_resp_psn,
                    err_wc_status=WC_STATUS.LOC_LEN_ERR,
                )

            # Generate CQE for read response
            read_cqe = CQE(
                wr_id=self.wr().id(),
                status=WC_STATUS.SUCCESS,
                opcode=WC_OPCODE.from_wr_op(self.wr().wr_op()),
                length=read_dlen,
                qpn=self.sqpn(),
                src_qp=self.dqpn(),
                wc_flags=EMPTY_WC_FLAG,
            )
            return read_cqe  # Return CQE to finish its corresponding WR

        self.inc_cpsn()  # Increase current PSN for next read response packet
        return None  # Still expect read response, not done yet


class RetryLogic:
    def __init__(self, send_q):
        self.send_q = send_q
        # The request WR SSN -> WorkReqCtx
        self.pending_wr_ctx_dict = {}
        # The request packet PSN -> WR SSN
        self.req_pkt_psn_wr_ssn_dict = {}
        # Keep track of the oldest sent packet
        self.oldest_sent_ts_ns = None

        self.pending_rd_atomic_wr_num = 0

    def resp_logic(self):
        return self.send_q.resp_logic

    def has_wr(self, wr_ssn):
        return wr_ssn in self.pending_wr_ctx_dict

    def rd_atomic_wr_num(self):
        return self.pending_rd_atomic_wr_num

    def cq(self):
        return self.send_q.cq()

    def empty(self):
        is_empty = not self.pending_wr_ctx_dict
        if is_empty:
            assert (
                not self.req_pkt_psn_wr_ssn_dict
            ), "req_pkt_psn_wr_ssn_dict should be empty"
        return is_empty

    def pending_wr_num(self):
        return len(self.pending_wr_ctx_dict)

    def nssn(self):  # Next SQ SSN
        return self.send_q.nssn()

    def npsn(self):  # Next SQ PSN
        return self.send_q.npsn()

    # def epsn(self):  # Expected RQ PSN
    #     return self.send_ctx.epsn()

    def mpsn(self):  # Min unacked SQ PSN
        return self.send_q.mpsn()

    def sqpn(self):  # Source QPN
        return self.send_q.sqpn()

    def dqpn(self):  # Destination QPN
        return self.send_q.dqpn()

    def rnr_retry(self):
        return self.send_q.rnr_retry()

    def retry_cnt(self):
        return self.send_q.retry_cnt()

    def timeout(self):
        return self.send_q.timeout()

    def add_wr_ctx(self, wr, wr_ssn):
        self.pending_wr_ctx_dict[wr_ssn] = WorkReqCtx(wr)

        read_or_atomic = WR_OPCODE.RDMA_READ == wr.wr_op() or WR_OPCODE.atomic(
            wr.wr_op()
        )
        if read_or_atomic:
            self.pending_rd_atomic_wr_num += 1
        if read_or_atomic or (SEND_FLAGS.SIGNALED & wr.flags()):
            self.update_oldest_sent_ts()  # Update oldest_sent_ts if is None

    def add_req_pkt(self, wr_ssn, pkt):
        pkt_psn = pkt[BTH].psn
        wr_ctx = self.get_wr_ctx(wr_ssn)
        self.req_pkt_psn_wr_ssn_dict[pkt_psn] = wr_ssn
        wr_ctx.add_req_pkt(pkt)

    def has_req_psn(self, req_psn):
        return req_psn in self.req_pkt_psn_wr_ssn_dict

    def has_resp_psn(self, resp_psn):
        return self.send_q.resp_logic.has_resp_psn(resp_psn)

    def get_read_resp_info(self, read_wr_ssn, read_resp_psn):
        return self.resp_logic().get_read_resp_info(read_wr_ssn, read_resp_psn)

    def get_wr_ssn_by_psn(self, pkt_psn):
        return self.req_pkt_psn_wr_ssn_dict[pkt_psn]

    def get_wr_ctx(self, wr_ssn):
        wr_ctx = self.pending_wr_ctx_dict[wr_ssn]
        return wr_ctx

    def delete_wr_ctx(self, ssn_to_delete):
        wr_ctx = self.pending_wr_ctx_dict.pop(ssn_to_delete)
        wr_op = wr_ctx.wr().wr_op()
        if wr_op == WR_OPCODE.RDMA_READ or WR_OPCODE.atomic(wr_op):
            self.pending_rd_atomic_wr_num -= 1
            assert (
                self.pending_rd_atomic_wr_num >= 0
            ), "pending_rd_atomic_wr_num should not < 0"
        # Clean up finished request PSN
        wr_pkt_psn_lst = wr_ctx.get_pkt_psn_lst()
        for req_pkt_psn in wr_pkt_psn_lst:
            del self.req_pkt_psn_wr_ssn_dict[req_pkt_psn]
        return wr_ctx

    def flush(self):
        for _, wr_ctx in self.pending_wr_ctx_dict.items():
            pending_sr = wr_ctx.wr()
            flush_pending_cqe = CQE(
                wr_id=pending_sr.id(),
                status=WC_STATUS.WR_FLUSH_ERR,
                opcode=WC_OPCODE.from_wr_op(pending_sr.wr_op()),
                length=pending_sr.len(),
                qpn=self.sqpn(),
                src_qp=self.dqpn(),
                wc_flags=EMPTY_WC_FLAG,
            )
            self.cq().push(flush_pending_cqe)
            # self.delete_wr(pending_ssn) BUG: cannot iterate a dictory and remove from it
        self.pending_wr_ctx_dict.clear()  # Delete all pending WR
        self.req_pkt_psn_wr_ssn_dict.clear()  # Delete all pending request data

    # oldest_sent_ts_ns is updated in 1 case:
    # - oldest_sent_ts_ns is None and there's new packet to send
    def update_oldest_sent_ts(self):
        if self.oldest_sent_ts_ns is None:
            if not self.empty():  # There are unacked requests
                self.oldest_sent_ts_ns = time.time_ns()
                logging.debug(
                    f"set oldest_sent_ts_ns={self.oldest_sent_ts_ns} to current timestamp"
                )
            else:
                logging.debug(f"no pending requests, oldest_sent_ts_ns remains to None")
                # self.oldest_sent_ts_ns = None  # No outstanding request
        logging.debug(
            f"oldest_sent_ts_ns={self.oldest_sent_ts_ns} is set, no need to update"
        )

    # oldest_sent_ts_ns is reset in 2 cases:
    # - ACK or NAK received
    # - timeout detected and retry
    def reset_oldest_sent_ts(self):
        if self.empty():  # There are no unakced requests
            logging.debug(f"reset oldest_sent_ts_ns to None, since no pending requests")
            self.oldest_sent_ts_ns = None
        else:
            cur_ts_ns = time.time_ns()
            logging.debug(f"reset oldest_sent_ts_ns={cur_ts_ns}")
            self.oldest_sent_ts_ns = cur_ts_ns

    def check_timeout_and_retry(self):
        if self.oldest_sent_ts_ns is not None:
            cur_ts_ns = time.time_ns()
            timeout_ns = Util.timeout_to_ns(self.timeout())
            if self.oldest_sent_ts_ns + timeout_ns < cur_ts_ns:
                assert (
                    Util.psn_compare(
                        self.mpsn(),
                        self.npsn(),
                        self.npsn(),
                    )
                    < 0
                ), "when timeout there should have outstanding requests"
                logging.info(
                    f"SQ={self.sqpn()} detected timeout, timeout_ns={timeout_ns}, \
                        cur_ts_ns={cur_ts_ns}, oldest_sent_ts_ns={self.oldest_sent_ts_ns}, \
                        wait_time_ns={cur_ts_ns - self.oldest_sent_ts_ns}, \
                        and retry from PSN={self.mpsn()} to PSN={self.npsn()} (not included)"
                )
                self.partial_retry_one_wr(
                    psn_begin_retry=self.mpsn(),
                    retry_type=RETRY_TYPE.TIMEOUT,
                )  # Only retry oldest WR

    # There is 2 case to partially retry one WR:
    # - timeout retry the oldest unacked request
    # - the first packets retried by RNR NAK or NAK seq err is not the first packet of a WR
    # This function might not retry the whole WR, specified by psn_begin_retry
    def partial_retry_one_wr(self, psn_begin_retry, retry_type):
        ssn_to_retry = self.get_wr_ssn_by_psn(psn_begin_retry)
        return self.maybe_retry_one_wr(ssn_to_retry, retry_type, psn_begin_retry)

    def maybe_retry_one_wr(self, ssn_to_retry, retry_type, psn_begin_retry=None):
        wr_ctx = self.pending_wr_ctx_dict[ssn_to_retry]
        psn_end_retry = (wr_ctx.first_psn() + wr_ctx.pkt_num()) % MAX_PSN
        if psn_begin_retry is None:
            psn_begin_retry = wr_ctx.first_psn()
        else:
            assert (
                Util.psn_compare(
                    wr_ctx.first_psn(),
                    psn_begin_retry,
                    self.npsn(),
                )
                <= 0
            ), "wr_ctx.first_psn() should <= retry_from_psn"
            assert (
                Util.psn_compare(
                    psn_begin_retry,
                    psn_end_retry,
                    self.npsn(),
                )
                <= 0
            ), "retry_from_psn should <= retry_end_psn"

        # Must retry each packet in PSN order
        for retry_psn in Util.psn_range(psn_begin_retry, psn_end_retry):
            pkt_to_retry = wr_ctx.get_req_pkt(retry_psn)
            self.send_retry_pkt(
                wr_ssn=ssn_to_retry,
                req_pkt=pkt_to_retry,
                retry_type=retry_type,
                partial_read_retry=False,
            )
        return ssn_to_retry

    # There are 3 cases to retry multiple packets:
    # - RNR NAK retry the specified request
    # - NAK sequence error received, retry all request packets after the specified PSN
    # - implicit NAK, retry all request packets after the implicit NAK PSN
    def retry_pkts(self, psn_begin_retry, retry_type):
        logging.debug(
            f"need to retry from PSN={psn_begin_retry}, retry_type={retry_type}"
        )
        # Maybe partial retry the WR specified by psn_begin_retry
        cur_retry_ssn = None
        if self.has_req_psn(psn_begin_retry):
            cur_retry_ssn = self.partial_retry_one_wr(psn_begin_retry, retry_type)
        else:
            cur_retry_ssn = self.partial_read_retry(
                partial_read_resp_psn=psn_begin_retry,
                retry_type=retry_type,
            )
        logging.debug(
            f"finished retry current SSN={cur_retry_ssn} and PSN={psn_begin_retry}"
        )
        next_retry_ssn = Util.next_ssn(cur_retry_ssn)

        # Must retry each WR in SSN order
        for retry_wr_ssn in Util.ssn_range(next_retry_ssn, self.nssn()):
            self.maybe_retry_one_wr(retry_wr_ssn, retry_type)

    # As for read request, since it might have multiple response packets, in case of retry,
    # the retry might start from the middle of read response, this is partial retry for read request.
    # As for send/write request, partial retry is not a problem.
    # As for atomic request, no partial retry issue.
    def partial_read_retry(self, partial_read_resp_psn, retry_type):
        assert not self.has_req_psn(
            partial_read_resp_psn
        ), f"partial_read_resp_psn={partial_read_resp_psn} should be \
                a mid or last read request PSN and not in req_pkt_psn_wr_ssn_dict"
        assert self.resp_logic().has_resp_psn(
            partial_read_resp_psn
        ), "incorrect NAK sequence error PSN to retry, \
            it should be in read_resp_psn_wr_ssn_dict"
        (
            retry_read_wr_ssn,
            orig_read_req_psn,
        ) = self.resp_logic().get_read_wr_ssn_orig_req_psn_by_resp_psn(
            partial_read_resp_psn
        )
        orig_read_wr_ssn = self.get_wr_ssn_by_psn(orig_read_req_psn)
        assert (
            retry_read_wr_ssn == orig_read_wr_ssn
        ), "retry_read_wr_ssn shoud == orig_read_wr_ssn"
        orig_read_wr_ctx = self.get_wr_ctx(orig_read_wr_ssn)
        orig_read_req = orig_read_wr_ctx.get_req_pkt(orig_read_req_psn)

        # Build a new read request,
        # but its PSN is within the range of the read response to the original read request
        retry_read_req = copy.deepcopy(orig_read_req)
        retry_read_req[BTH].psn = partial_read_resp_psn
        (
            retry_read_req[RETH].va,
            retry_read_req[RETH].dlen,
            remaining_read_resp_pkt_num,
        ) = self.get_read_resp_info(orig_read_wr_ssn, partial_read_resp_psn)

        assert (
            retry_read_req[RETH].dlen != 0
        ), "retry read request DMA length should not be zero, otherwise no need to retry"
        self.send_retry_pkt(
            wr_ssn=orig_read_wr_ssn,
            req_pkt=retry_read_req,
            retry_type=retry_type,
            partial_read_retry=True,
        )

        logging.debug(
            f"original read request of PSN={orig_read_req_psn} is retried, \
                the retried read request PSN={partial_read_resp_psn}, \
                which will expect {remaining_read_resp_pkt_num} read response packets"
        )
        return orig_read_wr_ssn

    def send_retry_pkt(self, wr_ssn, req_pkt, retry_type, partial_read_retry):
        req_pkt_psn = req_pkt[BTH].psn
        wr_ctx = self.get_wr_ctx(wr_ssn)
        if partial_read_retry:
            # For partial read retry,
            # it'll generate a read request with different PSN as the origianl read request
            self.add_req_pkt(wr_ssn, req_pkt)
        if retry_type == RETRY_TYPE.RNR:
            inc_res = wr_ctx.rnr_retry_inc(req_pkt_psn, self.rnr_retry())
            if not inc_res:  # RNR retry limit exceeded
                logging.error(
                    f"SQ={self.sqpn()} already RNR retried {self.rnr_retry()} times \
                        to send packet with PSN={req_pkt_psn}"
                )
                raise SQLocalErrException(
                    send_q=self.send_q,
                    err_pkt_psn=req_pkt_psn,
                    err_wc_status=WC_STATUS.RNR_RETRY_EXC_ERR,
                )
        elif RETRY_TYPE.non_rnr_retry(retry_type):
            inc_res = wr_ctx.other_retry_inc(req_pkt_psn, self.retry_cnt())
            if not inc_res:  # Retry limit exceeded
                logging.error(
                    f"SQ={self.sqpn()} already other retried {self.retry_cnt()} times \
                        to send packet with PSN={req_pkt_psn}"
                )
                raise SQLocalErrException(
                    send_q=self.send_q,
                    err_pkt_psn=req_pkt_psn,
                    err_wc_status=WC_STATUS.RETRY_EXC_ERR,
                )
        else:
            assert False, f"BUG: unsupported retry type: {retry_type}"

        logging.info(
            f"SQ={self.sqpn()} send retry request packet with PSN={req_pkt_psn} \
                for WR SSN={wr_ssn} with retry_type={retry_type}, \
                rnr_retry_num={wr_ctx.rnr_retry_num(req_pkt_psn)}, \
                other_retry_num={wr_ctx.other_retry_num(req_pkt_psn)}"
        )
        self.send_q.do_send_pkt(req_pkt)


class RespLogic:
    def __init__(self, send_q, sq_psn, wr_ssn):
        self.send_q = send_q
        self.min_unacked_psn = sq_psn
        self.min_unakced_wr_ssn = wr_ssn
        self.pre_resp_pkt_op = None
        # The read response packet PSN -> (read WR SSN, read request PSN)
        self.read_resp_psn_wr_ssn_dict = {}
        # The read request SSN -> ReadRespCtx
        self.read_resp_ctx_dict = {}

    def modify(self, sq_psn=None):
        if sq_psn is not None:
            self.min_unacked_psn = sq_psn

    def pd(self):
        return self.send_q.qp.pd

    def cq(self):
        return self.send_q.cq

    def npsn(self):  # Next SQ PSN
        return self.send_q.npsn()

    def mpsn(self):  # Min unacked SQ PSN
        return self.min_unacked_psn

    def mssn(self):  # Min unacked WR SSN
        return self.min_unakced_wr_ssn

    def sqpn(self):  # Source QPN
        return self.send_q.sqpn()

    def dqpn(self):  # Destination QPN
        return self.send_q.dqpn()

    def retry_logic(self):
        return self.send_q.retry_logic

    def has_resp_psn(self, resp_psn):
        return resp_psn in self.read_resp_psn_wr_ssn_dict

    def empty(self):
        is_empty = not self.read_resp_ctx_dict
        if is_empty:
            assert (
                not self.read_resp_psn_wr_ssn_dict
            ), "read_resp_psn_wr_ssn_dict should be empty"
        return is_empty

    def add_resp_ctx(self, wr_ssn, resp_ctx):
        self.read_resp_ctx_dict[wr_ssn] = resp_ctx

    def add_expect_read_resp_psn(
        self,
        read_resp_pkt_psn,
        read_wr_ssn,
        read_req_psn,
    ):
        self.read_resp_psn_wr_ssn_dict[read_resp_pkt_psn] = (
            read_wr_ssn,
            read_req_psn,
        )

    def get_read_wr_ssn_orig_req_psn_by_resp_psn(self, read_resp_psn):
        read_wr_ssn, orig_read_req_psn = self.read_resp_psn_wr_ssn_dict[read_resp_psn]
        return (read_wr_ssn, orig_read_req_psn)

    def get_read_resp_info(self, read_wr_ssn, read_resp_psn):
        read_resp_ctx = self.read_resp_ctx_dict[read_wr_ssn]
        (
            read_va,
            remaining_dlen,
            remaining_read_resp_pkt_num,
        ) = read_resp_ctx.get_resp_info(read_resp_psn)
        return (
            read_va,
            remaining_dlen,
            remaining_read_resp_pkt_num,
        )

    def flush(self):
        # Clear all pending WR, packets
        self.read_resp_psn_wr_ssn_dict.clear()  # Delete all pending read response data
        self.read_resp_ctx_dict.clear()  # Delete all pending read response context data

    # min_unacked_psn is updated in 2 cases:
    # - explicit ACK received
    # - implicit ACK
    def update_min_unacked_psn(self, min_unacked_psn):
        if self.min_unacked_psn != min_unacked_psn:
            self.min_unacked_psn = min_unacked_psn

    def is_expected_resp(self, resp_psn):
        if self.mpsn() == self.npsn():
            # No response expected
            return False
        else:
            assert (
                Util.psn_compare(
                    self.mpsn(),
                    self.npsn(),
                    self.npsn(),
                )
                < 0
            ), "min unacked PSN not < SQ PSN"
            if (
                Util.psn_compare(self.mpsn(), resp_psn, self.npsn()) <= 0
                and Util.psn_compare(self.npsn(), resp_psn, self.npsn()) > 0
            ):
                return True
            else:
                # Either dup or illegal response
                return False

    def handle_response(self, resp_pkt):
        rc_op = resp_pkt[BTH].opcode
        resp_pkt_psn = resp_pkt[BTH].psn
        if self.is_expected_resp(resp_pkt_psn):
            if not Util.check_pre_cur_ops(self.pre_resp_pkt_op, rc_op):
                # Handle locally detected error: Bad response / Requester Class B
                logging.error(
                    f"SQ={self.sqpn()} previous response and current opcode sequence is illegal: \
                        previous response opcode={self.pre_resp_pkt_op}, \
                        current response opcode={rc_op}"
                )
                raise SQLocalErrException(
                    send_q=self.send_q,
                    err_pkt_psn=resp_pkt_psn,
                    err_wc_status=WC_STATUS.BAD_RESP_ERR,
                )

            self.pre_resp_pkt_op = rc_op  # Update pre_resp_pkt_op to current one
            self.handle_expected_resp(resp_pkt)
        else:
            # Do not update pre_resp_pkt_op for duplicate packet or ghost response
            self.handle_dup_or_illegal_resp(resp_pkt)

    def handle_dup_or_illegal_resp(self, resp):
        if self.mpsn() == self.npsn():  # No response expected
            logging.info(
                f"SQ={self.sqpn()} received ghost response: {resp.show(dump=True)}"
            )
        else:  # SQ discard duplicate or illegal response, except for unsolicited flow control credit
            psn_comp_res = Util.psn_compare(resp[BTH].psn, self.mpsn(), self.npsn())
            assert psn_comp_res != 0, "should handle duplicate or illegal response"
            if psn_comp_res < 0:  # Dup resp
                logging.debug(
                    f"SQ={self.sqpn()} received duplicate response: {resp.show(dump=True)}"
                )
                nxt_psn = Util.next_psn(resp[BTH].psn)
                if nxt_psn == self.mpsn():  # Unsolicited flow control credit
                    assert (
                        AETH in resp
                    ), "unsolicited flow control credit ACK should have AETH"
                    assert (
                        resp[AETH].code == 0
                    ), "unsolicited flow control credit ACK code should be 0"
                    credit_cnt = resp[AETH].value
                    logging.debug(
                        f"SQ={self.sqpn()} received unsolicited flow control credit={credit_cnt}"
                    )
            else:  # Illegal response, just discard
                assert (
                    Util.psn_compare(
                        self.npsn(),
                        resp[BTH].psn,
                        self.npsn(),
                    )
                    <= 0
                ), "should be illegal response"
                logging.debug(
                    f"SQ={self.sqpn()} received illegal response: {resp.show(dump=True)}"
                )

    # There are 4 case to delete outstanding WQE:
    # - ACK received, delete finished send or write WR
    # - unrecoverable NAK received, delete NAK related WR
    # - read response received, delete finished read WR
    # - atomic response received, delete finished atomic WR
    def delete_wr(self, ssn_to_delete, wr_ctx):
        assert (
            self.min_unakced_wr_ssn == ssn_to_delete
        ), "it must ACK to WR in SSN order"
        self.min_unakced_wr_ssn = Util.next_ssn(ssn_to_delete)

        wr_op = wr_ctx.wr().wr_op()
        if wr_op == WR_OPCODE.RDMA_READ:  # Clean up read response context
            read_resp_ctx = self.read_resp_ctx_dict.pop(ssn_to_delete)
            # Cleanup finished read response PSN
            for resp_pkt_psn in read_resp_ctx.resp_psn_lst():
                del self.read_resp_psn_wr_ssn_dict[resp_pkt_psn]
        logging.debug(
            f"SQ={self.sqpn()} removed finished WR SSN={ssn_to_delete}, \
                min_unakced_wr_ssn={self.min_unakced_wr_ssn}"
        )

    def handle_expected_resp(self, resp):
        rc_op = resp[BTH].opcode
        resp_psn = resp[BTH].psn
        assert self.is_expected_resp(
            resp_psn
        ), "should expect valid response, not duplicate or illegal one"
        cur_wr_ssn = None
        if self.retry_logic().has_req_psn(resp_psn):
            cur_wr_ssn = self.retry_logic().get_wr_ssn_by_psn(resp_psn)
        else:
            assert RC.read_resp(rc_op) or (
                rc_op == RC.ACKNOWLEDGE and resp[AETH].code != 0
            ), f"response to read request must be read response or NAK, \
                but response rc_op={rc_op}"
            cur_wr_ssn, _ = self.get_read_wr_ssn_orig_req_psn_by_resp_psn(resp_psn)
        logging.debug(f"received response to cur_wr_ssn={cur_wr_ssn}, PSN={resp_psn}")

        # Coalesce ACK
        assert (
            Util.psn_compare(self.mpsn(), resp_psn, self.npsn()) <= 0
        ), "min_unacked_psn shoud <= resp_psn"
        # Coalesce ACK except read response last, which is only to ACK the whole read request
        implicit_ack_wr_num = 0
        if rc_op != RC.RDMA_READ_RESPONSE_LAST:
            for unacked_wr_ssn in Util.ssn_range(self.mssn(), cur_wr_ssn):
                cqe = self.ack_send_or_write_req(unacked_wr_ssn)
                implicit_ack_wr_num += 1
                if cqe is not None:
                    # Do not generate CQE for implicit ACK-ed send and write operations
                    # self.cq().push(cqe)
                    # Delete completed WR
                    self.send_q.delete_wr(unacked_wr_ssn)
            # Update min_unacked_psn up to the input response PSN (which is not ACK yet)
            self.update_min_unacked_psn(resp_psn)

        cqe = None
        if RC.read_resp(rc_op):
            cqe = self.handle_read_resp(resp, cur_wr_ssn)
        elif rc_op == RC.ATOMIC_ACKNOWLEDGE:
            cqe = self.handle_atomic_ack(resp, cur_wr_ssn)
        elif rc_op == RC.ACKNOWLEDGE:
            cqe = self.handle_ack_nak(resp, cur_wr_ssn)
        else:
            assert False, f"BUG: unsupported response opcode={rc_op}"

        if (
            AETH in resp and resp[AETH].code == 0
        ):  # ACK received, update min_unacked_psn
            # Update min_unacked_psn to next PSN
            self.update_min_unacked_psn(Util.next_psn(resp_psn))
        if cqe is not None:
            self.cq().push(cqe)
            # Delete completed WR
            self.send_q.delete_wr(cur_wr_ssn)

        logging.debug(
            f"min unacked PSN={self.mpsn()}, \
                next PSN={self.npsn()}, \
                implicit_ack_wr_num={implicit_ack_wr_num}, \
                pending_rd_atomic_wr_num={self.retry_logic().rd_atomic_wr_num()}"
        )

    def ack_send_or_write_req(self, send_or_write_wr_ssn, psn_to_ack=None):
        # ACK the whole request WR or ACK the request WR up to the input PSN
        wr_ctx = self.retry_logic().get_wr_ctx(send_or_write_wr_ssn)
        wr_op = wr_ctx.wr().wr_op()
        if WR_OPCODE.send(wr_op) or WR_OPCODE.write(wr_op):
            ack_whole_wr = False
            if psn_to_ack is None:
                ack_whole_wr = True
            else:
                pkt_to_ack = wr_ctx.get_req_pkt(psn_to_ack)
                rc_op = pkt_to_ack[BTH].opcode
                # Only to explicit or implicit ACK send and write
                # Generate CQE if the packet to ack is the last one
                ack_whole_wr = RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op)
            if ack_whole_wr:
                # Generate CQE for each acked send or write WR
                cqe = CQE(
                    wr_id=wr_ctx.wr().id(),
                    status=WC_STATUS.SUCCESS,
                    opcode=WC_OPCODE.from_wr_op(wr_op),
                    length=wr_ctx.data_size(),
                    qpn=self.sqpn(),
                    src_qp=self.dqpn(),
                    # Requester side CQE no need to handle IBV_WC_WITH_IMM or IBV_WC_WITH_INV
                    wc_flags=EMPTY_WC_FLAG,
                )
                return cqe
            return None
        else:  # Implicit NAK for read and atomic operations
            psn_to_retry = wr_ctx.first_psn()
            logging.info(
                f"SQ={self.sqpn()} has implicit ACK-ed packtes, \
                    needs to retry from SSN={send_or_write_wr_ssn}, \
                    and PSN={psn_to_retry}"
            )
            raise SQRetryException(
                send_q=self.send_q,
                psn_begin_retry=psn_to_retry,
                retry_type=RETRY_TYPE.IMPLICIT,
            )

    def handle_ack_nak(self, ack_pkt, send_or_write_wr_ssn):
        assert ack_pkt[BTH].opcode == RC.ACKNOWLEDGE, "should be ack response"
        cqe = None
        # AETH.code {0: "ACK", 1: "RNR", 2: "RSVD", 3: "NAK"}
        if ack_pkt[AETH].code == 0:  # ACK
            cqe = self.ack_send_or_write_req(
                send_or_write_wr_ssn=send_or_write_wr_ssn, psn_to_ack=ack_pkt[BTH].psn
            )

        # NAK invalid request / remote access / remote operation error, no retry
        elif ack_pkt[AETH].code == 3 and ack_pkt[AETH].value in [1, 2, 3]:
            err_pkt_psn = ack_pkt[BTH].psn
            raise SQNakErrException(
                send_q=self.send_q,
                err_pkt_psn=err_pkt_psn,
                err_wc_status=WC_STATUS.from_nak(ack_pkt[AETH].value),
            )

        elif ack_pkt[AETH].code == 1:  # RNR NAK, should retry
            rnr_psn = ack_pkt[BTH].psn
            rnr_wait_timer = ack_pkt[AETH].value
            if (
                self.send_q.min_rnr_timer() == 0
            ):  # 0 represents the largest RNR timer 655.36ms
                rnr_wait_timer = self.send_q.min_rnr_timer()
            elif self.send_q.min_rnr_timer() > ack_pkt[AETH].value:
                self.send_q.min_rnr_timer()  # Choose the larger RNR timer
            wait_time_ns = Util.rnr_timer_to_ns(rnr_wait_timer)
            # Handle RNR NAK wait time
            wait_time_secs = wait_time_ns / 1_000_000_000
            # Wait the time specified by rnr_wait_timer before retry
            time.sleep(wait_time_secs)
            logging.info(
                f"SQ={self.sqpn()} received RNR NAK with PSN={rnr_psn}, \
                    and rnr_wait_timer={rnr_wait_timer}, \
                    wait_time_ns={wait_time_ns}, \
                    min_rnr_timer={self.send_q.min_rnr_timer()}"
            )
            raise SQRetryException(
                send_q=self.send_q,
                psn_begin_retry=rnr_psn,
                retry_type=RETRY_TYPE.RNR,
            )

        elif (
            ack_pkt[AETH].code == 3 and ack_pkt[AETH].value == 0
        ):  # NAK seq error, should retry
            seq_err_psn = ack_pkt[BTH].psn
            logging.info(
                f"SQ={self.sqpn()} received NAK SEQ ERR with PSN={seq_err_psn}"
            )
            raise SQRetryException(
                send_q=self.send_q,
                psn_begin_retry=seq_err_psn,
                retry_type=RETRY_TYPE.SEQ,
            )

        else:
            # TODO: check whether SQ discard illegal ACK or not
            logging.info(
                f"received reserved AETH code or reserved AETH NAK value \
                    or unsported AETH NAK value: {ack_pkt.show(dump=True)}"
            )

        return cqe

    def handle_read_resp(self, read_resp_pkt, read_wr_ssn):
        read_resp_ctx = self.read_resp_ctx_dict[read_wr_ssn]
        read_cqe = read_resp_ctx.commit_resp_pkt(read_resp_pkt)
        return read_cqe

    def handle_atomic_ack(self, atomic_ack, atomic_wr_ssn):
        rc_op = atomic_ack[BTH].opcode
        atomic_ack_psn = atomic_ack[BTH].psn
        assert rc_op == RC.ATOMIC_ACKNOWLEDGE, "should be atomic ack"
        # TODO: handle atomic NAK, does atomic have NAK?
        assert atomic_ack[AETH].code == 0, "atomic ack is NAK"

        atomic_wr_ctx = self.retry_logic().get_wr_ctx(atomic_wr_ssn)
        atomic_laddr = atomic_wr_ctx.laddr()
        atomic_lkey = atomic_wr_ctx.lkey()

        # Because bind_layers(AETH, AtomicAckETH) is not work, so use Raw instead of AtomicAckETH
        if len(atomic_ack[Raw].load) != ATOMIC_BYTE_SIZE:
            logging.error("AtomicAckETH size not correct")
            return (WC_STATUS.LOC_LEN_ERR, atomic_ack_psn)
        atomic_mr = self.pd().get_mr(atomic_lkey)
        atomic_mr.write(byte_data=atomic_ack[Raw].load, addr=atomic_laddr)
        atomic_cqe = CQE(
            wr_id=atomic_wr_ctx.wr().id(),
            status=WC_STATUS.SUCCESS,
            opcode=WC_OPCODE.from_wr_op(atomic_wr_ctx.wr().wr_op()),
            length=ATOMIC_BYTE_SIZE,
            qpn=self.sqpn(),
            src_qp=self.dqpn(),
            wc_flags=EMPTY_WC_FLAG,
        )
        return atomic_cqe


class TXLogic:
    def __init__(self, send_q, sq_psn):
        self.send_q = send_q
        self.sq_psn = sq_psn

    def modify(self, sq_psn):
        if sq_psn is not None:
            self.sq_psn = sq_psn % MAX_PSN

    def pd(self):
        return self.sq().qp.pd

    def sq(self):
        return self.send_q

    def sqpn(self):
        return self.sq().sqpn()

    def dqpn(self):
        return self.sq().dqpn()

    def npsn(self):
        return self.sq_psn

    def mtu(self):
        return self.sq().mtu()

    def flags(self):
        return self.sq().flags()

    def resp_logic(self):
        return self.sq().resp_logic

    def retry_logic(self):
        return self.sq().retry_logic

    def send_req_pkt(self, cssn, send_req):
        self.sq().send_req_pkt(cssn, send_req)

    def process_req(self):
        if not self.sq().busy():
            wr, cssn = self.sq().pop()
            req_pkt_num = None
            if WR_OPCODE.send(wr.wr_op()):
                req_pkt_num = self.process_send_req(wr, cssn)
            elif WR_OPCODE.write(wr.wr_op()):
                req_pkt_num = self.process_write_req(wr, cssn)
            elif WR_OPCODE.RDMA_READ == wr.wr_op():
                req_pkt_num = self.process_read_req(wr, cssn)
            elif WR_OPCODE.atomic(wr.wr_op()):
                req_pkt_num = self.process_atomic_req(wr, cssn)
            else:
                assert (
                    False
                ), f"BUG: SQ={self.sqpn()} met unsupported opcode: {wr.wr_op()}"
            self.sq_psn = (self.sq_psn + req_pkt_num) % MAX_PSN
            return True
        else:
            logging.debug(
                f"SQ={self.sqpn()} has sent too many requests, \
                    {self.retry_logic().rd_atomic_wr_num()} outstanding read/atomic requests"
            )
            return False

    def process_send_req(self, sr, cssn):
        assert WR_OPCODE.send(sr.wr_op()), "should be send operation"

        addr = sr.laddr()
        send_size = sr.len()
        send_data = b""
        if send_size:
            mr = self.pd().get_mr(sr.lkey())
            send_data = mr.read(addr=addr, size=send_size)

        send_req_pkt_num = Util.compute_wr_pkt_num(sr.len(), self.mtu())
        cpsn = self.sq_psn
        dqpn = self.dqpn()
        ackreq = True if SEND_FLAGS.SIGNALED & sr.flags() else False
        solicited = True if SEND_FLAGS.SOLICITED & sr.flags() else False

        if send_req_pkt_num > 1:
            send_bth = BTH(
                opcode=RC.SEND_FIRST,
                psn=cpsn,
                dqpn=dqpn,
                ackreq=False,
                solicited=False,
            )
            send_req = send_bth / Raw(load=send_data[0 : self.mtu()])
            self.send_req_pkt(cssn, send_req)

            send_req_mid_pkt_num = send_req_pkt_num - 2
            for i in range(send_req_mid_pkt_num):
                send_bth = BTH(
                    opcode=RC.SEND_MIDDLE,
                    psn=cpsn + i + 1,
                    dqpn=dqpn,
                    ackreq=False,
                    solicited=False,
                )
                send_req = send_bth / Raw(
                    load=send_data[((i + 1) * self.mtu()) : ((i + 2) * self.mtu())]
                )
                self.send_req_pkt(cssn, send_req)

        rc_op = None
        if send_req_pkt_num == 1:
            if sr.wr_op() == WR_OPCODE.SEND_WITH_IMM:
                rc_op = RC.SEND_ONLY_WITH_IMMEDIATE
            elif sr.wr_op() == WR_OPCODE.SEND_WITH_INV:
                rc_op = RC.SEND_ONLY_WITH_INVALIDATE
            else:
                rc_op = RC.SEND_ONLY
        else:
            if sr.wr_op() == WR_OPCODE.SEND_WITH_IMM:
                rc_op = RC.SEND_LAST_WITH_IMMEDIATE
            elif sr.wr_op() == WR_OPCODE.SEND_WITH_INV:
                rc_op = RC.SEND_LAST_WITH_INVALIDATE
            else:
                rc_op = RC.SEND_LAST
        send_bth = BTH(
            opcode=rc_op,
            psn=cpsn + send_req_pkt_num - 1,
            dqpn=dqpn,
            ackreq=ackreq,
            solicited=solicited,
        )
        send_req = None
        if RC.has_imm(rc_op):
            imm_data = ImmDt(data=sr.imm_data_or_inv_rkey())
            send_req = send_bth / imm_data
        elif RC.has_inv(rc_op):
            send_ieth = IETH(rkey=sr.imm_data_or_inv_rkey())
            send_req = send_bth / send_ieth
        else:
            send_req = send_bth
        if send_size > 0:
            raw_pkt = Raw(
                load=send_data[((send_req_pkt_num - 1) * self.mtu()) : send_size]
            )
            send_req = send_req / raw_pkt
        self.send_req_pkt(cssn, send_req)
        return send_req_pkt_num

    def process_write_req(self, sr, cssn):
        assert WR_OPCODE.write(sr.wr_op()), "should be write operation"

        addr = sr.laddr()
        write_size = sr.len()
        write_data = b""
        if write_size:
            mr = self.pd().get_mr(sr.lkey())
            write_data = mr.read(addr=addr, size=write_size)

        write_req_pkt_num = Util.compute_wr_pkt_num(write_size, self.mtu())
        cpsn = self.sq_psn
        dqpn = self.dqpn()
        ackreq = True if SEND_FLAGS.SIGNALED & sr.flags() else False
        solicited = False

        write_reth = RETH(va=sr.raddr(), rkey=sr.rkey(), dlen=write_size)
        if write_req_pkt_num > 1:
            write_bth = BTH(
                opcode=RC.RDMA_WRITE_FIRST,
                psn=cpsn,
                dqpn=dqpn,
                ackreq=False,
                solicited=False,
            )
            write_req = write_bth / write_reth / Raw(load=write_data[0 : self.mtu()])
            self.send_req_pkt(cssn, write_req)

            write_req_mid_pkt_num = write_req_pkt_num - 2
            for i in range(write_req_mid_pkt_num):
                write_bth = BTH(
                    opcode=RC.RDMA_WRITE_MIDDLE,
                    psn=cpsn + i + 1,
                    dqpn=dqpn,
                    ackreq=False,
                    solicited=False,
                )
                write_req = write_bth / Raw(
                    load=write_data[((i + 1) * self.mtu()) : ((i + 2) * self.mtu())]
                )
                self.send_req_pkt(cssn, write_req)

        rc_op = None
        solicited = False
        if write_req_pkt_num == 1:
            if sr.wr_op() == WR_OPCODE.RDMA_WRITE_WITH_IMM:
                rc_op = RC.RDMA_WRITE_ONLY_WITH_IMMEDIATE
                solicited = True if SEND_FLAGS.SOLICITED & sr.flags() else False
            else:
                rc_op = RC.RDMA_WRITE_ONLY
        else:
            if sr.wr_op() == WR_OPCODE.RDMA_WRITE_WITH_IMM:
                rc_op = RC.RDMA_WRITE_LAST_WITH_IMMEDIATE
                solicited = True if SEND_FLAGS.SOLICITED & sr.flags() else False
            else:
                rc_op = RC.RDMA_WRITE_LAST
        write_bth = BTH(
            opcode=rc_op,
            psn=cpsn + write_req_pkt_num - 1,
            dqpn=dqpn,
            ackreq=ackreq,
            solicited=solicited,
        )
        write_req = None
        if RC.only_req_pkt(rc_op):
            if RC.has_imm(rc_op):
                # RDMA_WRITE_ONLY_WITH_IMMEDIATE use RETHImmDt, instead of RETH/ImmDt
                reth_imm_data = RETHImmDt(
                    va=sr.raddr(),
                    rkey=sr.rkey(),
                    dlen=write_size,
                    data=sr.imm_data_or_inv_rkey(),
                )
                write_req = write_bth / reth_imm_data
            else:
                write_req = write_bth / write_reth
        else:
            if RC.has_imm(rc_op):
                imm_data = ImmDt(data=sr.imm_data_or_inv_rkey())
                write_req = write_bth / imm_data
            else:
                write_req = write_bth
        if write_size > 0:
            raw_pkt = Raw(
                load=write_data[((write_req_pkt_num - 1) * self.mtu()) : write_size]
            )
            write_req = write_req / raw_pkt
        self.send_req_pkt(cssn, write_req)
        return write_req_pkt_num

    def process_read_req(self, sr, cssn):
        assert sr.wr_op() == WR_OPCODE.RDMA_READ, "should be read operation"

        read_size = sr.len()
        read_resp_pkt_num = Util.compute_wr_pkt_num(read_size, self.mtu())
        cpsn = self.sq_psn
        dqpn = self.dqpn()

        read_bth = BTH(
            opcode=RC.RDMA_READ_REQUEST,
            psn=cpsn,
            dqpn=dqpn,
            ackreq=True,
        )
        read_reth = RETH(va=sr.raddr(), rkey=sr.rkey(), dlen=read_size)
        read_req = read_bth / read_reth

        read_resp_ctx = ReadRespCtx(
            send_q=self.sq(),
            read_wr_ssn=cssn,
            read_wr=sr,
            read_req_pkt=read_req,
            read_resp_pkt_num=read_resp_pkt_num,
        )
        self.resp_logic().add_resp_ctx(cssn, read_resp_ctx)
        self.send_req_pkt(cssn, read_req)
        return read_resp_pkt_num

    def process_atomic_req(self, sr, cssn):
        assert WR_OPCODE.atomic(sr.wr_op()), "should be atomic operation"

        rc_op = (
            RC.COMPARE_SWAP
            if sr.wr_op() == WR_OPCODE.ATOMIC_CMP_AND_SWP
            else RC.FETCH_ADD
        )
        cpsn = self.sq_psn
        dqpn = self.dqpn()
        atomic_bth = BTH(
            opcode=rc_op,
            psn=cpsn,
            dqpn=dqpn,
            ackreq=True,
        )
        atomic_eth = AtomicETH(
            va=sr.raddr(),
            rkey=sr.rkey(),
            comp=sr.comp(),
            swap=sr.swap(),
        )
        atomic_req = atomic_bth / atomic_eth
        self.sq().send_req_pkt(cssn, atomic_req)
        atomic_req_pkt_num = 1  # Atomic request only has 1 packet
        return atomic_req_pkt_num


class SQ:
    def __init__(self, qp, cq, sq_psn, sq_draining=False):
        self.sq = []
        self.qp = qp
        self.cq = cq
        self.ssn = 1
        self.sq_draining = sq_draining
        self.tx_logic = TXLogic(send_q=self, sq_psn=sq_psn)
        self.resp_logic = RespLogic(send_q=self, sq_psn=sq_psn, wr_ssn=self.ssn)
        self.retry_logic = RetryLogic(send_q=self)

    def modify(
        self,
        sq_psn=None,
        sq_draining=None,
    ):
        if sq_draining is not None:
            self.sq_draining = sq_draining
        # TXLogic keeps track of sq_psn
        self.tx_logic.modify(sq_psn=sq_psn)
        # min_unacked_psn should be updated each time sq_psn updated
        self.resp_logic.modify(sq_psn=sq_psn)

    # Used for test purpose only, to test NAK seq err retry case
    def set_min_unacked_psn(self, unacked_psn):
        self.resp_logic.update_min_unacked_psn(unacked_psn)

    def rnr_retry(self):
        return self.qp.rnr_retry

    def retry_cnt(self):
        return self.qp.retry_cnt

    def timeout(self):
        return self.qp.timeout

    def min_rnr_timer(self):
        return self.qp.min_rnr_timer

    def push(self, wr):
        wr_op = wr.wr_op()
        # TODO: handle immediate errors, unsupported opcode
        assert (
            WR_OPCODE.send(wr_op)
            or WR_OPCODE.write(wr_op)
            or WR_OPCODE.atomic(wr_op)
            or wr_op == WR_OPCODE.RDMA_READ
        ), f"send WR has unsupported opcode={wr_op}"
        if wr_op in [
            WR_OPCODE.SEND_WITH_IMM,
            WR_OPCODE.SEND_WITH_INV,
            WR_OPCODE.RDMA_WRITE_WITH_IMM,
        ]:
            # TODO: handle immediate errors
            assert (
                wr.imm_data_or_inv_rkey() is not None
            ), "send/write with immediate data or send with invalidate \
                requires send WR has imm_data_or_inv_rkey"
        if wr.len() > 0:
            local_key = wr.lkey()
            if wr_op == WR_OPCODE.RDMA_READ:
                local_mr = self.qp.pd.check_mr_access(
                    RC.RDMA_READ_RESPONSE_ONLY, local_key
                )
                # TODO: handle immediate error, read should have local write permission
                assert (
                    local_mr is not None
                ), "read op should have write permission to local MR"
            elif wr_op in [
                WR_OPCODE.RDMA_READ,
                WR_OPCODE.ATOMIC_CMP_AND_SWP,
                WR_OPCODE.ATOMIC_FETCH_AND_ADD,
            ]:
                local_mr = self.qp.pd.check_mr_access(RC.ATOMIC_ACKNOWLEDGE, local_key)
                # TODO: handle immediate error, atomic should have local write permission
                assert (
                    local_mr is not None
                ), "atomic op should have write permission to local MR"
            # TODO: handle immediate error
            assert self.qp.pd.check_mr_size(
                lrkey=local_key,
                addr=wr.laddr(),
                data_size=wr.len(),
            ), "send WR local SG is not within its MR"

        self.sq.append(wr)

    def pop(self):
        assert not self.sq_draining, "SQ is draining, cannot pop WQE"
        wr = self.sq.pop(0)
        cssn = self.ssn
        self.retry_logic.add_wr_ctx(
            wr, cssn
        )  # Add WR to RetryLogic first, before send packets
        self.ssn = (self.ssn + 1) % MAX_SSN
        return (wr, cssn)

    def max_dest_rd_atomic(self):
        return self.qp.max_dest_rd_atomic

    def busy(self):  # If True, no resource to process more pending request WR
        return (
            self.retry_logic.rd_atomic_wr_num() >= self.max_dest_rd_atomic()
            or self.retry_logic.pending_wr_num() >= MAX_PENDING_REQ_NUM
        )

    def has_psn(self, pkt_psn):
        return self.resp_logic.has_resp_psn(pkt_psn) or self.retry_logic.has_req_psn(
            pkt_psn
        )

    def empty(self):
        return not bool(self.sq)

    def sqpn(self):
        return self.qp.qpn()

    def dqpn(self):
        return self.qp.dqpn()

    def nssn(self):  # Next SQ SSN
        return self.ssn

    def mpsn(self):  # Min unacked PSN
        return self.resp_logic.mpsn()

    def npsn(self):  # Next SQ PSN
        return self.tx_logic.npsn()

    def mtu(self):
        return self.qp.mtu()

    def flags(self):  # QP access flags
        return self.qp.flags()

    def flush(self):
        self.resp_logic.flush()
        self.retry_logic.flush()
        while not self.empty():
            flush_sr, _ = self.pop()
            flush_cqe = CQE(
                wr_id=flush_sr.wr().id(),
                status=WC_STATUS.WR_FLUSH_ERR,
                opcode=WC_OPCODE.from_wr_op(flush_sr.wr().wr_op()),
                length=flush_sr.wr().len(),
                qpn=self.sqpn(),
                src_qp=self.dqpn(),
                wc_flags=EMPTY_WC_FLAG,
            )
            self.cq.push(flush_cqe)

    def delete_wr(self, ssn_to_delete):
        wr_ctx = self.retry_logic.delete_wr_ctx(ssn_to_delete)
        self.resp_logic.delete_wr(ssn_to_delete, wr_ctx)  # Delete the NAK specified WR

    def goto_err_state(self, err_pkt_psn, err_wc_status):
        self.qp.modify_qp(qps=QPS.ERR)
        # Explicit NAK corresponding request
        nak_ssn = self.retry_logic.get_wr_ssn_by_psn(err_pkt_psn)
        nak_sr_ctx = self.retry_logic.get_wr_ctx(nak_ssn)
        nak_cqe = CQE(
            wr_id=nak_sr_ctx.wr().id(),
            status=err_wc_status,
            opcode=WC_OPCODE.from_wr_op(nak_sr_ctx.wr().wr_op()),
            length=nak_sr_ctx.wr().len(),
            qpn=self.sqpn(),
            src_qp=self.dqpn(),
            wc_flags=EMPTY_WC_FLAG,
        )
        self.cq.push(nak_cqe)
        self.delete_wr(nak_ssn)  # Delete the NAK specified WR

        # All submitted WR in SQ/RD will be completed with flush in error
        self.qp.flush()

    def do_send_pkt(self, pkt):
        if Raw in pkt:
            pkt = Util.add_padding_if_needed(pkt)
        l3_pkt = IP(dst=self.qp.dip()) / UDP(dport=ROCE_PORT, sport=self.sqpn()) / pkt
        logging.debug(
            f"SQ={self.sqpn()} sent to IP={self.qp.dip()} a request: {l3_pkt.show(dump=True)}"
        )
        send(l3_pkt)

    def send_req_pkt(self, wr_ssn, req_pkt):
        req_pkt_psn = req_pkt[BTH].psn
        logging.debug(
            f"SQ={self.sqpn()} send request packet with PSN={req_pkt_psn} for WR SSN={wr_ssn}"
        )
        self.retry_logic.add_req_pkt(wr_ssn, req_pkt)
        self.do_send_pkt(req_pkt)

    def process_req(self):
        self.tx_logic.process_req()

    def handle_response(self, resp_pkt):
        self.resp_logic.handle_response(resp_pkt)
