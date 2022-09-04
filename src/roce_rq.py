import logging
import sys
import time

from roce import *
from roce_enum import *
from roce_util import *
from scapy.all import *


class RQNakErrException(Exception):
    def __init__(self, rx_logic, req, err_wc_status, nak_wr=None):
        self.rx_logic = rx_logic
        self.req = req
        self.err_wc_status = err_wc_status
        self.nak_wr = nak_wr

    def process_nak_err(self):
        self.rx_logic.process_nak_err(
            req=self.req,
            err_wc_status=self.err_wc_status,
            nak_wr=self.nak_wr,
        )


class RQNakRnrException(Exception):
    def __init__(self, rx_logic, req):
        self.rx_logic = rx_logic
        self.req = req

    def process_nak_rnr(self):
        self.rx_logic.process_nak_rnr(self.req)


class RQNakSeqException(Exception):
    def __init__(self, rx_logic):
        self.rx_logic = rx_logic

    def process_nak_seq_err(self):
        self.rx_logic.process_nak_seq_err()


class RecvWR:
    def __init__(self, sgl, wr_id=0):
        self.sgl = sgl
        self.wr_id = wr_id

    def id(self):
        return self.wr_id

    def lkey(self):
        return self.sgl.lkey()

    def addr(self):
        return self.sgl.addr()

    def len(self):
        return self.sgl.len()


class ReqCtx:
    def __init__(self, first_rc_op, rx_logic, cpsn):
        self.wr_opcode = WR_OPCODE.from_rc_op(first_rc_op)
        self.recv_logic = rx_logic
        self.cur_psn = cpsn
        self.req_addr = None
        self.req_dlen = None
        self.req_rkey = None
        self.recv_wr = None

    def wr_op(self):
        return self.wr_opcode

    def addr(self):
        return self.req_addr

    def data_size(self):
        return self.req_dlen

    def lrkey(self):
        return self.req_rkey

    def sqpn(self):
        return self.rx_logic().sqpn()

    def dqpn(self):
        return self.rx_logic().dqpn()

    def cpsn(self):
        return self.cur_psn

    def mtu(self):
        return self.rx_logic().mtu()

    def pd(self):
        return self.rx_logic().pd()

    def cq(self):
        return self.rx_logic().cq()

    def rq(self):
        return self.rx_logic().rq()

    def wr(self):
        return self.recv_wr

    def rx_logic(self):
        return self.recv_logic

    def msn(self):
        return self.rx_logic().msn


class SendReqCtx(ReqCtx):
    def __init__(self, rx_logic, send_req_pkt):
        rc_op = send_req_pkt[BTH].opcode
        ReqCtx.__init__(
            self,
            first_rc_op=rc_op,
            rx_logic=rx_logic,
            cpsn=send_req_pkt[BTH].psn,
        )
        self.recv_wr = None
        self.send_mr = None
        self.cur_send_offset = 0
        self.send_req_lst = []
        self.imm_data = None
        self.inv_rkey = None

        assert RC.send(rc_op), "should be send request"
        assert RC.first_req_pkt(rc_op) or RC.only_req_pkt(
            rc_op
        ), "should be be first or only send request packet"
        # Handle RNR NAK: Resources Not Ready Error / Responder Class B
        if self.rq().empty():
            logging.info(
                f"RQ={self.sqpn()} has no receive WR, response RNR NAK to send request"
            )
            raise RQNakRnrException(
                rx_logic=self.rx_logic(),
                req=send_req_pkt,
            )
        self.recv_wr = self.rq().pop()
        if Raw in send_req_pkt:
            # Handle remote access error: R_Key Violation / Responder Class C
            self.send_mr = self.pd().check_mr_access(rc_op, self.recv_wr.lkey())
            if not self.send_mr:
                logging.error("receive WR MR no access permission for send request")
                raise RQNakErrException(
                    rx_logic=self.rx_logic(),
                    req=send_req_pkt,
                    err_wc_status=WC_STATUS.REM_ACCESS_ERR,
                    nak_wr=self.wr(),
                )

    def add_req_pkt(self, send_req_pkt):
        # assert Raw in send_req_pkt, 'non-first send request should have non-empty raw data'
        self.send_req_lst.append(send_req_pkt)
        self.cur_send_offset += Util.raw_data_len(send_req_pkt)
        if self.cur_send_offset > 0:
            if not self.pd().check_mr_size(
                lrkey=self.lrkey(),
                addr=self.addr(),
                data_size=self.data_size(),
            ):
                # Handle invalid request error: Length errors / Responder Class C
                logging.error("no enough receive buffer for send request")
                raise RQNakErrException(
                    rx_logic=self.rx_logic(),
                    req=send_req_pkt,
                    err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
                    nak_wr=self.wr(),
                )

    def addr(self):
        return self.wr().addr()

    def data_size(self):
        return self.cur_send_offset

    def lrkey(self):
        return self.wr().lkey()

    def commit(self):
        send_offset = 0
        last_rc_op = None
        last_send_req_pkt = None
        for send_req_pkt in self.send_req_lst:
            send_offset += Util.write_to_mr(
                dst_mr=self.send_mr,
                write_to_mr_addr=self.addr() + send_offset,
                data_pkt=send_req_pkt,
            )
            last_send_req_pkt = send_req_pkt
            last_rc_op = send_req_pkt[BTH].opcode

        cqe_wc_flags = EMPTY_WC_FLAG
        cqe_imm_data_or_inv_rkey = None

        if RC.has_imm(last_rc_op):
            self.imm_data = last_send_req_pkt[ImmDt].data
            cqe_wc_flags |= WC_FLAGS.WITH_IMM
            cqe_imm_data_or_inv_rkey = self.imm_data
        elif RC.has_inv(last_rc_op):
            self.inv_rkey = last_send_req_pkt[
                IETH
            ].rkey  # TODO: handle rkey invalidation
            cqe_wc_flags |= WC_FLAGS.WITH_INV
            cqe_imm_data_or_inv_rkey = self.inv_rkey

        # Generate CQE for received send request
        cqe = CQE(
            wr_id=self.wr().id(),
            status=WC_STATUS.SUCCESS,
            opcode=WC_OPCODE.from_rc_op(last_rc_op),
            length=self.data_size(),
            qpn=self.sqpn(),
            src_qp=self.dqpn(),
            wc_flags=cqe_wc_flags,
            imm_data_or_inv_rkey=cqe_imm_data_or_inv_rkey,
        )
        self.cq().push(cqe)

        if send_req_pkt[BTH].solicited:
            pass  # TODO: handle solicited event


class WriteReqCtx(ReqCtx):
    def __init__(self, rx_logic, write_req_pkt):
        rc_op = write_req_pkt[BTH].opcode
        ReqCtx.__init__(
            self,
            first_rc_op=rc_op,
            rx_logic=rx_logic,
            cpsn=write_req_pkt[BTH].psn,
        )
        self.write_mr = None
        self.cur_write_offset = 0
        self.write_req_lst = []
        self.imm_data = None
        self.recv_wr = None

        if RC.has_imm(rc_op):
            self.req_rkey = write_req_pkt[RETHImmDt].rkey
            self.req_addr = write_req_pkt[RETHImmDt].va
            self.req_dlen = write_req_pkt[RETHImmDt].dlen
        else:
            self.req_rkey = write_req_pkt[RETH].rkey
            self.req_addr = write_req_pkt[RETH].va
            self.req_dlen = write_req_pkt[RETH].dlen

        assert RC.write(rc_op), "should be write request"
        assert RC.first_req_pkt(rc_op) or RC.only_req_pkt(
            rc_op
        ), "should be be first or only write request packet"
        if self.data_size() > 0:
            # Handle remote access error: R_Key Violation / Responder Class C
            self.write_mr = self.pd().check_mr_access(rc_op, self.lrkey())
            if not self.write_mr:
                logging.error("write MR no access permission for write request")
                raise RQNakErrException(
                    rx_logic=self.rx_logic(),
                    req=write_req_pkt,
                    err_wc_status=WC_STATUS.REM_ACCESS_ERR,
                )
            if not self.pd().check_mr_size(
                lrkey=self.lrkey(),
                addr=self.addr(),
                data_size=self.data_size(),
            ):
                # Handle invalid request error: Length errors / Responder Class C
                logging.error("write MR no enough space for write request")
                # TODO: double check write with imm error case, it should report write length error,
                # before consume a RR and generate a CQE with error status
                raise RQNakErrException(
                    rx_logic=self.rx_logic(),
                    req=write_req_pkt,
                    err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
                )
        else:
            assert Raw not in write_req_pkt and RC.only_req_pkt(
                rc_op
            ), "write request with DMA length as 0 should have no data"

    def add_req_pkt(self, write_req_pkt):
        self.write_req_lst.append(write_req_pkt)
        self.cur_write_offset += Util.raw_data_len(write_req_pkt)

    def commit(self):
        write_offset = 0
        last_rc_op = None
        last_write_req_pkt = None
        for write_req_pkt in self.write_req_lst:
            write_offset += Util.write_to_mr(
                dst_mr=self.write_mr,
                write_to_mr_addr=self.addr() + write_offset,
                data_pkt=write_req_pkt,
            )
            last_write_req_pkt = write_req_pkt
            last_rc_op = write_req_pkt[BTH].opcode
        assert RC.last_req_pkt(last_rc_op) or RC.only_req_pkt(
            last_rc_op
        ), "no last or only request packet received yet"

        if RC.has_imm(last_rc_op):
            self.imm_data = last_write_req_pkt[RETHImmDt].data
            # Handle invalid request error: Length error / Responder Class C
            if self.cur_write_offset != self.data_size():
                logging.error("write request data size not match DMA length")
                # TODO: double check write with imm error case, it should report write length error,
                # before consume a RR and generate a CQE with error status
                raise RQNakErrException(
                    rx_logic=self.rx_logic(),
                    req=last_write_req_pkt,
                    err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
                )

            cqe_wc_flags = WC_FLAGS.WITH_IMM
            cqe_imm_data = write_req_pkt[RETHImmDt].data
            # Handle RNR NAK: Resources Not Ready Error / Responder Class B
            if self.rq().empty():
                logging.info(
                    f"RQ={self.sqpn()} is empty but write with immediate data needs to consume a receive WR"
                )
                raise RQNakRnrException(
                    rx_logic=self.rx_logic(),
                    req=write_req_pkt,
                )
            self.recv_wr = self.rq().pop()
            # Generate CQE for received write with imm request
            cqe = CQE(
                wr_id=self.wr().id(),
                status=WC_STATUS.SUCCESS,
                opcode=WC_OPCODE.from_rc_op(last_rc_op),
                length=self.data_size(),
                qpn=self.sqpn(),
                src_qp=self.dqpn(),
                wc_flags=cqe_wc_flags,
                imm_data_or_inv_rkey=self.imm_data,
            )
            self.cq().push(cqe)

            if write_req_pkt[BTH].solicited:
                pass  # TODO: handle solicited event


class ReadReqCtx(ReqCtx):
    def __init__(self, rx_logic, read_req_pkt):
        rc_op = read_req_pkt[BTH].opcode
        ReqCtx.__init__(
            self,
            first_rc_op=rc_op,
            rx_logic=rx_logic,
            cpsn=read_req_pkt[BTH].psn,
        )
        self.read_mr = None
        self.read_resp_lst = []

        assert rc_op == RC.RDMA_READ_REQUEST, "should be read request"

        self.req_dlen = read_req_pkt[RETH].dlen
        self.req_addr = read_req_pkt[RETH].va
        self.req_rkey = read_req_pkt[RETH].rkey

        if self.data_size() > 0:
            # Handle remote access error: R_Key Violation / Responder Class C
            self.read_mr = self.pd().check_mr_access(rc_op=rc_op, lrkey=self.lrkey())
            if not self.read_mr:
                logging.error("MR has no access permission for read request")
                raise RQNakErrException(
                    rx_logic=self.rx_logic(),
                    req=read_req_pkt,
                    err_wc_status=WC_STATUS.REM_ACCESS_ERR,
                )
            if not self.pd().check_mr_size(
                lrkey=self.lrkey(),
                addr=self.addr(),
                data_size=self.data_size(),
            ):
                # Handle invalid request error: Length errors / Responder Class C
                logging.error("MR has no enough space for read request")
                raise RQNakErrException(
                    rx_logic=self.rx_logic(),
                    req=read_req_pkt,
                    err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
                )

    def commit(self):
        read_req_size = self.data_size()
        cpsn = self.cpsn()
        dqpn = self.dqpn()
        pmtu = self.mtu()
        read_data = None
        if self.read_mr is not None:
            read_data = self.read_mr.read(addr=self.addr(), size=read_req_size)
        else:
            assert read_req_size == 0, "read_req_size should be 0"
        read_resp_pkt_num = Util.compute_wr_pkt_num(read_req_size, pmtu)
        read_aeth = AETH(code="ACK", value=CREDIT_CNT_INVALID, msn=self.msn())
        if read_resp_pkt_num > 1:
            read_resp_bth = BTH(
                opcode=RC.RDMA_READ_RESPONSE_FIRST,
                psn=cpsn,
                dqpn=dqpn,
            )
            read_resp = read_resp_bth / read_aeth / Raw(load=read_data[0:pmtu])
            self.read_resp_lst.append(read_resp)
            # self.send_pkt(read_resp, save_pkt = False)

            read_resp_mid_pkt_num = read_resp_pkt_num - 2
            for i in range(read_resp_mid_pkt_num):
                read_resp_bth = BTH(
                    opcode=RC.RDMA_READ_RESPONSE_MIDDLE,
                    psn=cpsn + i + 1,
                    dqpn=dqpn,
                )
                read_resp = read_resp_bth / Raw(
                    load=read_data[((i + 1) * pmtu) : ((i + 2) * pmtu)]
                )
                self.read_resp_lst.append(read_resp)

        rc_op = None
        if read_resp_pkt_num == 1:
            rc_op = RC.RDMA_READ_RESPONSE_ONLY
        else:
            rc_op = RC.RDMA_READ_RESPONSE_LAST
        read_resp_bth = BTH(
            opcode=rc_op,
            psn=cpsn + read_resp_pkt_num - 1,
            dqpn=dqpn,
        )
        read_resp = read_resp_bth / read_aeth
        if read_req_size > 0:
            read_resp = read_resp / Raw(
                load=read_data[((read_resp_pkt_num - 1) * pmtu) : read_req_size]
            )
        self.read_resp_lst.append(read_resp)
        return self.read_resp_lst


class AtomicReqCtx(ReqCtx):
    def __init__(self, rx_logic, atomic_req_pkt):
        rc_op = atomic_req_pkt[BTH].opcode
        ReqCtx.__init__(
            self,
            first_rc_op=rc_op,
            rx_logic=rx_logic,
            cpsn=atomic_req_pkt[BTH].psn,
        )
        self.rc_op = rc_op  # To distinguish atomic type
        self.atomic_mr = None

        assert RC.atomic(rc_op), "should be atomic request"

        self.req_rkey = atomic_req_pkt[AtomicETH].rkey
        self.req_addr = atomic_req_pkt[AtomicETH].va
        self.comp = atomic_req_pkt[AtomicETH].comp
        self.swap = atomic_req_pkt[AtomicETH].swap

        # Handle remote access error: R_Key Violation / Responder Class C
        self.atomic_mr = self.pd().check_mr_access(rc_op, self.lrkey())
        if not self.atomic_mr:
            logging.error("atomic MR no access permission for atomic request")
            raise RQNakErrException(
                rx_logic=self.rx_logic(),
                req=atomic_req_pkt,
                err_wc_status=WC_STATUS.REM_ACCESS_ERR,
            )
        if not self.pd().check_mr_size(
            lrkey=self.lrkey(),
            addr=self.addr(),
            data_size=ATOMIC_BYTE_SIZE,
        ):
            # Handle invalid request error: Length errors / Responder Class C
            logging.error("atomic MR no enough space for atomic request")
            raise RQNakErrException(
                rx_logic=self.rx_logic(),
                req=atomic_req_pkt,
                err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
            )
        # Handle invalid request error: Misaligned ATOMIC / Responder Class C
        if not Util.check_addr_aligned(addr=self.addr(), mr=self.atomic_mr):
            logging.error("atomic request address is not 8-byte aligned")
            raise RQNakErrException(
                rx_logic=self.rx_logic(),
                req=atomic_req_pkt,
                err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
            )

    def commit(self):
        cpsn = self.cpsn()
        dqpn = self.dqpn()
        addr = self.addr()

        # TODO: need to lock orig
        orig = int.from_bytes(
            self.atomic_mr.read(
                addr=addr,
                size=ATOMIC_BYTE_SIZE,
            ),
            sys.byteorder,
        )
        if self.rc_op == RC.COMPARE_SWAP:
            if orig == self.comp:
                self.atomic_mr.write(
                    byte_data=self.swap.to_bytes(ATOMIC_BYTE_SIZE, sys.byteorder),
                    addr=addr,
                )
        elif self.rc_op == RC.FETCH_ADD:
            self.atomic_mr.write(
                byte_data=(orig + self.comp).to_bytes(ATOMIC_BYTE_SIZE, sys.byteorder),
                addr=addr,
            )
        else:
            assert False, f"BUG: invalid atomic opcode={self.rc_op}"

        ack_bth = BTH(
            opcode=RC.ATOMIC_ACKNOWLEDGE,
            psn=cpsn,
            dqpn=dqpn,
        )
        ack_aeth = AETH(code="ACK", value=CREDIT_CNT_INVALID, msn=self.msn())
        atomic_ack_eth = AtomicAckETH(orig=orig)
        atomic_ack = ack_bth / ack_aeth / atomic_ack_eth
        return atomic_ack


class RXLogic:
    def __init__(self, rq, rq_psn, roce_socket, recv_timeout_secs=1):
        self.recv_q = rq
        self.rq_psn = rq_psn % MAX_PSN

        self.msn = 0
        self.pending_req_ctx_dict = {}

        self.resp_pkt_dict = {}
        self.pre_req_pkt_op = None

        self.cur_req_idx = 0

        self.rnr_nak_wait_clear_ts_ns = 0
        self.nak_seq_err_pending = False

        self.roce_socket = roce_socket

        self.recv_timeout_secs = recv_timeout_secs

    def modify(self, rq_psn=None):
        if rq_psn is not None:
            self.rq_psn = rq_psn % MAX_PSN

    def clear_pending_retry_err(self):
        self.rnr_nak_wait_clear_ts_ns = 0
        self.nak_seq_err_pending = False

    def cq(self):
        return self.rq().cq()

    def pd(self):
        return self.rq().pd()

    def rq(self):
        return self.recv_q

    def sqpn(self):  # Source QPN
        return self.rq().sqpn()

    def dqpn(self):  # Destination QPN
        return self.rq().dqpn()

    def epsn(self):  # Next expected RQ PSN
        return self.rq_psn

    def mtu(self):
        return self.rq().mtu()

    def has_pending_retry_err(self):  # RNR or NAK seq err not clear
        cur_ts_ns = time.time_ns()
        rnr_nak_pending = cur_ts_ns <= self.rnr_nak_wait_clear_ts_ns
        logging.debug(
            f"nak_seq_err_pending={self.nak_seq_err_pending}, \
                rnr_nak_pending={rnr_nak_pending}"
        )
        return self.nak_seq_err_pending or rnr_nak_pending

    def is_expected_req(self, req_psn):
        return req_psn == self.epsn()

    def handle_request(self, req_pkt):
        rc_op = req_pkt[BTH].opcode
        assert RC.request(rc_op), "should be request opcode"
        if self.is_expected_req(req_pkt[BTH].psn):
            # Handle invalid request error: Out of Sequence OpCode / Responder Class C
            if not Util.check_pre_cur_ops(self.pre_req_pkt_op, rc_op):
                logging.error(
                    "previous request and current request opcode sequence is illegal"
                )
                raise RQNakErrException(
                    rx_logic=self,
                    req=req_pkt,
                    err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
                )
            # Handle invalid request error: Length errors / Responder Class C
            if not Util.check_pkt_size(self.rq().mtu(), req_pkt):
                logging.error("received packet size illegal")
                raise RQNakErrException(
                    rx_logic=self,
                    req=req_pkt,
                    err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
                )
            # Handle invalid request error: Unsupported or Reserved OpCode / Responder Class C
            if not Util.check_op_with_access_flags(rc_op, self.rq().flags()):
                logging.error("received packet has opcode without proper permission")
                raise RQNakErrException(
                    rx_logic=self,
                    req=req_pkt,
                    err_wc_status=WC_STATUS.REM_INV_REQ_ERR,
                )
            # RQ received request matches its ePSN and clear any previous NAK sequence error
            self.nak_seq_err_pending = False
            if RC.send(rc_op):
                self.handle_send_req(req_pkt)
            elif RC.write(rc_op):
                self.handle_write_req(req_pkt)
            elif rc_op == RC.RDMA_READ_REQUEST:
                self.handle_read_req(read_req_pkt=req_pkt, retry_read_req=False)
            elif RC.atomic(rc_op):
                self.handle_atomic_req(req_pkt)
            else:
                assert False, f"BUG: unknown request opcode={rc_op}"

            self.pre_req_pkt_op = rc_op
        else:
            self.handle_dup_or_illegal_req(req_pkt)

    def cur_ctx(self):
        assert (
            self.cur_req_idx in self.pending_req_ctx_dict
        ), "cur_req_idx should in pending_req_ctx_dict"
        return self.pending_req_ctx_dict[self.cur_req_idx]

    def add_req_ctx(self, req_ctx):
        next_idx = (self.cur_req_idx + 1) % MAX_PENDING_REQ_NUM
        # TODO: handle too many incoming requests
        assert (
            next_idx not in self.pending_req_ctx_dict
        ), "no resource to handle incoming request"
        self.cur_req_idx = next_idx
        self.pending_req_ctx_dict[self.cur_req_idx] = req_ctx

    def rm_cur_req_ctx(self):
        del self.pending_req_ctx_dict[self.cur_req_idx]

    def handle_send_req(self, send_req_pkt):
        rc_op = send_req_pkt[BTH].opcode
        if RC.first_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            send_req_ctx = SendReqCtx(rx_logic=self, send_req_pkt=send_req_pkt)
            self.add_req_ctx(send_req_ctx)
        self.handle_send_write_req_helper(send_req_pkt)

    def handle_write_req(self, write_req_pkt):
        rc_op = write_req_pkt[BTH].opcode
        if RC.first_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            write_req_ctx = WriteReqCtx(rx_logic=self, write_req_pkt=write_req_pkt)
            self.add_req_ctx(write_req_ctx)
        self.handle_send_write_req_helper(write_req_pkt)

    def handle_send_write_req_helper(self, req_pkt):
        rc_op = req_pkt[BTH].opcode
        req_ctx = self.cur_ctx()
        req_ctx.add_req_pkt(req_pkt)

        if RC.last_req_pkt(rc_op) or RC.only_req_pkt(rc_op):
            req_ctx.commit()
            self.rm_cur_req_ctx()
            self.msn = (self.msn + 1) % MAX_MSN  # Update MSN

        self.rq_psn = Util.next_psn(self.epsn())  # Update ePSN
        if req_pkt[BTH].ackreq:
            self.process_ack(req_pkt)

    def handle_read_req(self, read_req_pkt, retry_read_req=False):
        read_req_ctx = ReadReqCtx(rx_logic=self, read_req_pkt=read_req_pkt)
        self.add_req_ctx(read_req_ctx)
        read_resp_lst = read_req_ctx.commit()
        read_resp_pkt_num = len(read_resp_lst)
        for read_resp in read_resp_lst:
            self.send_pkt(
                read_resp, save_resp_pkt=False
            )  # Read never save response packets
        self.rm_cur_req_ctx()
        if not retry_read_req:
            self.msn = (self.msn + 1) % MAX_MSN  # Update MSN
            self.rq_psn = (self.epsn() + read_resp_pkt_num) % MAX_PSN  # Update ePSN

    def handle_atomic_req(self, atomic_req_pkt):
        atomic_req_ctx = AtomicReqCtx(rx_logic=self, atomic_req_pkt=atomic_req_pkt)
        self.add_req_ctx(atomic_req_ctx)
        atomic_resp_pkt = atomic_req_ctx.commit()
        self.send_pkt(atomic_resp_pkt)
        self.rm_cur_req_ctx()
        self.msn = (self.msn + 1) % MAX_MSN
        self.rq_psn = Util.next_psn(self.epsn())  # Update ePSN

    def send_pkt(self, resp, save_resp_pkt=True):
        if not self.rq().dqpn():
            assert False, f"BUG: RQ={self.sqpn()} has no destination QPN"
        elif not self.rq().dgid():
            assert False, f"BUG: RQ={self.sqpn()} has no destination GID"

        # We set resp hook point here because the RDMA part(transport layer) of package is assembled for routine process,
        # and then we can change some parts of it here to simulate an error or something else.
        # We don't need to change the content of network layer so we should not move this hook point down.
        if self.recv_q.resp_hook != None:
            resp, save_resp_pkt = self.recv_q.resp_hook(resp, save_resp_pkt)

        if Raw in resp:
            resp = Util.add_padding_if_needed(resp)
        pkt = (
            IP(dst=self.rq().dip())
            / UDP(dport=ROCE_PORT, sport=self.rq().sqpn())
            / resp
        )

        cpsn = pkt[BTH].psn
        if save_resp_pkt:
            self.resp_pkt_dict[cpsn] = pkt
        logging.debug(
            f"RQ={self.rq().sqpn()} send to IP={self.rq().dip()} a response: {pkt.show(dump=True)}"
        )
        send(pkt)

    def handle_dup_or_illegal_req(self, req):
        req_psn = req[BTH].psn
        psn_comp_res = Util.psn_compare(self.epsn(), req_psn, self.epsn())
        assert psn_comp_res != 0, "should handle duplicate or illegal request"
        if psn_comp_res > 0:  # Dup req
            logging.debug(
                f"RQ={self.sqpn()} received duplicate request: {req.show(dump=True)}"
            )
            rc_op = req[BTH].opcode
            if RC.send(rc_op) or RC.write(rc_op):
                dup_resp = self.resp_pkt_dict[req_psn]
                dup_resp[BTH].psn = self.epsn()  # Dup requst response has latest PSN
                self.send_pkt(dup_resp, save_resp_pkt=False)
            elif rc_op == RC.RDMA_READ_REQUEST:
                self.handle_read_req(read_req_pkt=req, retry_read_req=True)
            elif RC.atomic(rc_op):
                # TODO: check the dup atomic request is the same as before
                dup_resp = self.resp_pkt_dict[req_psn]
                if AtomicAckETH in dup_resp:
                    self.send_pkt(dup_resp, save_resp_pkt=False)
                else:
                    logging.debug(
                        f"RQ={self.rq().sqpn()} received duplicate atomic request: \
                            {req.show(dump=True)} but the response was not match: \
                            {dup_resp.show(dump=True)}"
                    )
        else:
            # Handle NAK sequence error: Out of Sequence Request Packet / Responder Class B
            logging.info(
                f"RQ={self.rq().sqpn()} had sequence error, ePSN={self.epsn()}, \
                    but received request: {req.show(dump=True)}"
            )
            raise RQNakSeqException(rx_logic=self)

    def process_ack(self, req):
        assert req[BTH].ackreq, "received request should ask for ack response"
        ack_bth = BTH(
            opcode=RC.ACKNOWLEDGE,
            psn=req[BTH].psn,
            dqpn=self.rq().dqpn(),
        )
        # TODO: support RQ flow control
        ack = ack_bth / AETH(code="ACK", value=CREDIT_CNT_INVALID, msn=self.msn)
        self.send_pkt(ack)

    def process_nak_rnr(self, req):
        if not self.has_pending_retry_err():
            rnr_wait_timer = self.rq().min_rnr_timer()
            rnr_nak_bth = BTH(
                opcode=RC.ACKNOWLEDGE,
                psn=req[BTH].psn,
                dqpn=self.rq().dqpn(),
            )
            rnr_nak_aeth = AETH(code="RNR", value=rnr_wait_timer, msn=self.msn)
            rnr_nak = rnr_nak_bth / rnr_nak_aeth
            self.send_pkt(rnr_nak)
            cur_ts_ns = time.time_ns()
            rnr_wait_time_ns = Util.rnr_timer_to_ns(rnr_wait_timer)
            # The timestamp RNR NAK wait timer to be cleared
            self.rnr_nak_wait_clear_ts_ns = cur_ts_ns + rnr_wait_time_ns
            logging.info(
                f"RQ={self.rq().sqpn()} sent a RNR NAK and set RNR clear timestamp: \
                    rnr_nak_wait_clear_ts_ns={self.rnr_nak_wait_clear_ts_ns}, \
                    rnr_wait_timer={rnr_wait_timer}, rnr_wait_time_ns={rnr_wait_time_ns}, \
                    cur_ts_ns={cur_ts_ns}"
            )
        else:
            logging.info(
                f"RQ={self.rq().sqpn()} already responsed a retry NAK \
                    no RNR NAK to response again before previous NAK retry error cleared"
            )

    def process_nak_seq_err(self):
        if not self.has_pending_retry_err():
            seq_nak_bth = BTH(
                opcode=RC.ACKNOWLEDGE,
                psn=self.epsn(),
                dqpn=self.rq().dqpn(),
            )
            seq_nak_aeth = AETH(code="NAK", value=0, msn=self.msn)
            seq_nak = seq_nak_bth / seq_nak_aeth
            self.send_pkt(seq_nak)
            self.nak_seq_err_pending = (
                True  # There is a NAK seq err needs to be cleared
            )
            logging.info(
                f"RQ={self.rq().sqpn()} sent a NAK seq err with ePSN={self.epsn()}"
            )
        else:
            logging.info(
                f"RQ={self.rq().sqpn()} already responsed a retry NAK, \
                    and now it can only response to request matches its ePSN"
            )

    def process_nak_err(self, req, err_wc_status, nak_wr=None):
        nak_err_bth = BTH(
            opcode=RC.ACKNOWLEDGE,
            psn=req[BTH].psn,
            dqpn=self.rq().dqpn(),
        )
        nak_err_value = RSRV_AETH_NAK_VAL
        if err_wc_status == WC_STATUS.REM_INV_REQ_ERR:
            nak_err_value = 1
            logging.error(
                f"RQ={self.rq().sqpn()} sent NAK remote invalid request error"
            )
        elif err_wc_status == WC_STATUS.REM_ACCESS_ERR:
            nak_err_value = 2
            logging.error(f"RQ={self.rq().sqpn()} sent NAK remote access error")
        elif err_wc_status == WC_STATUS.REM_OP_ERR:
            nak_err_value = 3
            logging.error(f"RQ={self.rq().sqpn()} sent NAK remote operation error")
        else:
            assert err_wc_status in [
                WC_STATUS.REM_INV_REQ_ERR,
                WC_STATUS.REM_ACCESS_ERR,
                WC_STATUS.REM_OP_ERR,
            ], "NAK error should be REM_INV_REQ_ERR, REM_ACCESS_ERR, REM_OP_ERR"
        nak_err_aeth = AETH(code="NAK", value=nak_err_value, msn=self.msn)
        nak_err = nak_err_bth / nak_err_aeth
        self.send_pkt(nak_err)
        self.rq().goto_err_state(req[BTH].opcode, err_wc_status, nak_wr=nak_wr)

    def flush(self):
        for _, req_ctx in self.pending_req_ctx_dict.items():
            pending_recv_wr = req_ctx.wr()
            if pending_recv_wr is not None:
                # Only send and write with imm has recv_wr
                flush_pending_cqe = CQE(
                    wr_id=pending_recv_wr.id(),
                    status=WC_STATUS.WR_FLUSH_ERR,
                    # TODO: BUG: for write imm, this WC_OPCODE is RDMA_WRITE not RECV_RDMA_WITH_IMM
                    opcode=WC_OPCODE.from_wr_op(QueueType.RQ, req_ctx.wr_op()),
                    length=pending_recv_wr.len(),
                    qpn=self.rq().sqpn(),
                    src_qp=self.rq().dqpn(),
                    wc_flags=EMPTY_WC_FLAG,
                )
                self.cq().push(flush_pending_cqe)
            # BUG: cannot iterate a dictory and remove from it

        # Clear all pending WR, packets
        self.pending_req_ctx_dict.clear()

    def recv_pkts(self, npkt, qpn=None, retry_handler=None, check_pkt=None):
        self.roce_socket.settimeout(self.recv_timeout_secs)
        if npkt == 0:  # TODO: better handle for timeout logic of each QP
            try:
                roce_bytes, _ = self.roce_socket.recvfrom(UDP_BUF_SIZE)
                assert (
                    False
                ), f"BUG: just wait for timeout and it should not receive any packet"
            except socket.timeout:
                logging.info("expect timeout successfully")
                try:
                    # Check request timeout and retry if any
                    self.qp.check_timeout_and_retry()
                except SQLocalErrException as local_err:
                    local_err.process_local_err()
        else:
            logging.debug(f"expect receiving {npkt} packets")
            opcodes = []
            pkt_idx = 0
            while pkt_idx < npkt:
                roce_bytes, peer_addr = self.roce_socket.recvfrom(UDP_BUF_SIZE)
                # TODO: handle non-RoCE packet
                roce_pkt = BTH(roce_bytes)
                dqpn = roce_pkt[BTH].dqpn
                # if roce_pkt[BTH].psn==10008 and roce_pkt[BTH].opcode==RC.SEND_MIDDLE:
                #     assert False, f'receive from peer={peer_addr} wrong packet={roce_pkt.show(dump=True)}'
                logging.debug(
                    f"received packet No. {pkt_idx + 1} for QP={dqpn} from IP={peer_addr}, \
                        total {npkt} packets expected"
                )
                # Skip unexpected packets and record warnings
                if qpn != None:
                    if roce_pkt[BTH].dqpn != qpn:
                        logging.warn(
                            f"expected qpn: {qpn}, received pkt's qpn: {roce_pkt[BTH].dqpn}"
                        )
                        continue
                if check_pkt:
                    check_pkt(roce_pkt)
                opcodes.append(self.recv_q.qp.recv_pkt(roce_pkt, retry_handler))
                pkt_idx += 1
            logging.debug(f"received {npkt} RoCE packets")
            return opcodes


class RQ:
    def __init__(self, qp, cq, rq_psn, roce_socket):
        self.rq = []
        self.qp = qp
        self.comp_queue = cq
        self.rx_logic = RXLogic(rq=self, rq_psn=rq_psn, roce_socket=roce_socket)
        self.resp_hook = None

    def modify(self, rq_psn=None):
        self.rx_logic.modify(rq_psn=rq_psn)

    def clear_pending_retry_err(self):
        self.rx_logic.clear_pending_retry_err()

    def cq(self):
        return self.comp_queue

    def pd(self):
        return self.qp.pd

    def mtu(self):
        return self.qp.mtu()

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

    def epsn(self):
        return self.rx_logic.epsn()

    def dgid(self):
        return self.qp.dgid()

    def dip(self):
        return self.qp.dip()

    def flags(self):
        return self.qp.flags()

    def min_rnr_timer(self):
        return self.qp.min_rnr_timer

    def flush(self):
        self.rx_logic.flush()
        while not self.empty():
            flush_rr = self.pop()
            flush_cqe = CQE(
                wr_id=flush_rr.id(),
                status=WC_STATUS.WR_FLUSH_ERR,
                opcode=None,  # TODO: make sure unused recv_wr has no opcode
                length=flush_rr.len(),
                qpn=self.sqpn(),
                src_qp=self.dqpn(),
                wc_flags=EMPTY_WC_FLAG,
            )
            self.cq().push(flush_cqe)

    def handle_request(self, req_pkt):  # Handle retry-able error here
        try:
            self.rx_logic.handle_request(req_pkt)
        except RQNakRnrException as err:
            err.process_nak_rnr()
        except RQNakSeqException as err:
            err.process_nak_seq_err()

    def goto_err_state(self, rc_op, err_wc_status, nak_wr=None):
        self.qp.modify_qp(qps=QPS.ERR)
        if nak_wr is not None:
            # Explicit NAK corresponding request
            nak_cqe = CQE(
                wr_id=nak_wr.id(),
                status=err_wc_status,
                opcode=WC_OPCODE.from_rc_op(rc_op),
                length=nak_wr.len(),
                qpn=self.sqpn(),
                src_qp=self.dqpn(),
                wc_flags=EMPTY_WC_FLAG,
            )
            self.cq().push(nak_cqe)
        else:
            self.qp.add_async_event(EVENT_TYPE.from_wc_status(err_wc_status))
        self.qp.flush()

    def reg_resp_hook(self, resp_hook):
        self.resp_hook = resp_hook

    def recv_pkts(self, npkt, retry_handler=None, check_pkt=None):
        return self.rx_logic.recv_pkts(
            npkt, qpn=self.qp.qp_num, retry_handler=retry_handler, check_pkt=check_pkt
        )
