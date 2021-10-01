import logging
import socket

from roce import *
from roce_enum import *
from roce_rq import *
from roce_sq import *
from roce_util import *
from scapy.all import *


class QP:
    def __init__(
        self,
        pd,
        cq,
        qpn,
        pmtu,
        access_flags,
        use_ipv6,
        rq_psn=0,
        sq_psn=0,
        pkey=DEFAULT_PKEY,
        sq_draining=0,
        max_rd_atomic=10,
        max_dest_rd_atomic=10,
        min_rnr_timer=10,
        timeout=10,
        retry_cnt=3,
        rnr_retry=3,
    ):
        self.pd = pd  # TODO: check pd match for each req
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
        self.dst_ip = None

        self.sq = SQ(
            qp=self,
            cq=cq,
            sq_psn=sq_psn,
            sq_draining=sq_draining,
        )
        self.rq = RQ(
            qp=self,
            cq=cq,
            rq_psn=rq_psn,
        )
        self.pd.add_qp(self)

    def modify_qp(
        self,
        qps=None,
        pmtu=None,
        rq_psn=None,
        sq_psn=None,
        dgid=None,
        dst_qpn=None,
        access_flags=None,
        pkey=None,
        sq_draining=None,
        max_rd_atomic=None,
        max_dest_rd_atomic=None,
        min_rnr_timer=None,
        timeout=None,
        retry_cnt=None,
        rnr_retry=None,
    ):
        if qps is not None:
            self.qps = qps
            if self.qps in [QPS.RTR, QPS.RTS]:
                logging.info(
                    f"QP={self.qpn()} clear retry error state, when set QPS back to RTR or RTS"
                )
                # TODO: check if other QPS states also need to clear retry error state
                self.rq.clear_pending_retry_err()
        if pmtu is not None:
            self.pmtu = pmtu
        if dgid is not None:
            self.dst_gid = dgid
            self.set_dst_ip()
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

        self.sq.modify(sq_psn=sq_psn, sq_draining=sq_draining)
        self.rq.modify(rq_psn=rq_psn)

    def set_dst_ip(self):
        # ip_hex = socket.inet_aton('192.168.122.190').hex()
        # dst_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(self.dgid))
        dst_ipv6 = socket.inet_ntop(socket.AF_INET6, self.dgid())
        dst_ipv4 = dst_ipv6.replace("::ffff:", "")
        self.dst_ip = dst_ipv6 if self.use_ipv6 else dst_ipv4

    # For test purpose only
    def set_min_unacked_psn(self, unacked_psn):
        self.sq.set_min_unacked_psn(unacked_psn)

    def dip(self):
        assert self.dst_ip is not None, "QP dest IP is none"
        return self.dst_ip

    def qpn(self):
        return self.qp_num

    def dqpn(self):
        return self.dst_qpn

    def npsn(self):
        return self.sq.npsn()

    def epsn(self):
        return self.rq.epsn()

    def dgid(self):
        return self.dst_gid

    def pkey(self):
        return self.partition_key

    def flags(self):
        return self.access_flags

    def mtu(self):
        return self.pmtu

    def status(self):
        return self.qps

    def reset_oldest_sent_ts(self):
        self.sq.retry_logic.reset_oldest_sent_ts()

    def check_timeout_and_retry(self):
        self.sq.retry_logic.check_timeout_and_retry()
        self.reset_oldest_sent_ts()  # Reset oldest_sent_ts when timeout retry

    def verify_pkt_head(self, pkt):
        # TODO: handle head verification
        assert pkt[BTH].dqpn == self.qpn(), "received packet QPN not match"
        assert pkt[BTH].opcode < 0x20, "only RC supported"
        assert pkt[BTH].version == 0, "header version must be zero"
        assert (
            pkt[BTH].pkey == self.pkey()
        ), "received packet PKEY not match"  # TODO: handle PKEY match rule
        return True

    def recv_pkt(self, pkt, retry_handler):
        assert self.qps in [QPS.RTS, QPS.RTR], "QP state is not RTS or RTR"

        logging.debug(
            f"QP={self.qpn()} received packet with length={len(pkt)}: "
            + pkt.show(dump=True)
        )
        rc_op = pkt[BTH].opcode

        # Handle head verification
        if not self.verify_pkt_head(pkt):
            logging.info(
                f"QP={self.qpn()} encountered packet head verification failure, \
                    drop packet={pkt.show(dump=True)}"
            )
            return rc_op # Just drop packet

        if RC.request(rc_op):
            try:
                self.rq.handle_request(pkt)
            except RQNakErrException as nak_err:
                nak_err.process_nak_err()
            except RQNakRnrException as rnr_err:
                rnr_err.process_nak_rnr()
            except RQNakSeqException as nak_seq_err:
                nak_seq_err.process_nak_seq_err()
        elif RC.response(rc_op):
            try:
                try:
                    self.sq.handle_response(pkt)
                except SQRetryException as retry_err:
                    if retry_handler is not None:
                        retry_handler()
                    retry_err.process_retry()
                except SQNakErrException as rmt_nak_err:
                    rmt_nak_err.process_nak_err()
            # When handling retry exception,
            # it might raise local exception if retry limit exceeded
            except SQLocalErrException as local_err:
                local_err.process_local_err()

            self.reset_oldest_sent_ts()  # Reset oldest_sent_ts when ACK or NAK received
        else:
            assert False, f"BUG: QP={self.qpn()} received unsupported opcode={rc_op}"
        
        return rc_op 

    def poll_cq(self):
        if not self.cq.empty():  # TODO: support seperate CQ for SQ and RQ
            return self.cq.pop()
        else:
            return None

    def post_send(self, send_wr):
        assert self.qps == QPS.RTS, "QP state is not RTS"
        self.sq.push(send_wr)

    def post_recv(self, recv_wr):
        assert self.qps in [QPS.RTS, QPS.RTR], "QP state is not RTS or RTR"
        self.rq.push(recv_wr)

    def process_one_sr(self):
        assert self.qps == QPS.RTS, "QP state is not RTS"
        return self.sq.process_req()

    def flush(self):  # Flush all WR in SQ/RQ
        # All pending processing send WR will be completed with flush in error
        self.sq.flush()
        # All pending processing receive WR will be completed with flush in error
        self.rq.flush()

    def add_async_event(self, event_type):
        self.event_queue.append(event_type)

    def get_async_event(self):
        pass  # TODO: implement async event


class RoCEv2:
    def __init__(self, pmtu=PMTU.MTU_256, use_ipv6=False, recv_timeout_secs=1):
        self.roce_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        roce_bind_addr = ("0.0.0.0", ROCE_PORT)
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
        qp = QP(
            pd=pd,
            cq=cq,
            qpn=qpn,
            access_flags=access_flags,
            pmtu=self.pmtu,
            use_ipv6=self.use_ipv6,
        )
        self.qp_dict[qpn] = qp
        return qp

    def mtu(self):
        return self.pmtu

    def clear_remaining_pkts(self, npkt):
        for idx in range(npkt):
            self.roce_sock.settimeout(self.recv_timeout_secs)
            roce_bytes, peer_addr = self.roce_sock.recvfrom(UDP_BUF_SIZE)
            roce_pkt = BTH(roce_bytes)
            dqpn = roce_pkt[BTH].dqpn
            pkt_psn = roce_pkt[BTH].psn
            logging.debug(
                f"received remaining packet No. {idx + 1} with PSN={pkt_psn}, \
                    for QP={dqpn} from IP={peer_addr}, total {npkt} packets expected"
            )

    def recv_pkts(self, npkt, retry_handler=None):
        self.roce_sock.settimeout(self.recv_timeout_secs)
        if npkt == 0:  # TODO: better handle for timeout logic of each QP
            try:
                roce_bytes, _ = self.roce_sock.recvfrom(UDP_BUF_SIZE)
                assert (
                    False
                ), f"BUG: just wait for timeout and it should not receive any packet"
            except socket.timeout:
                logging.info("expect timeout successfully")
                for dqpn, local_qp in self.qp_dict.items():
                    try:
                        # Check request timeout and retry if any
                        local_qp.check_timeout_and_retry()
                    except SQLocalErrException as local_err:
                        local_err.process_local_err()
        else:
            logging.debug(f"expect receiving {npkt} packets")
            opcodes = []
            for idx in range(npkt):
                roce_bytes, peer_addr = self.roce_sock.recvfrom(UDP_BUF_SIZE)
                # TODO: handle non-RoCE packet
                roce_pkt = BTH(roce_bytes)
                dqpn = roce_pkt[BTH].dqpn
                # if roce_pkt[BTH].psn==10008 and roce_pkt[BTH].opcode==RC.SEND_MIDDLE:
                #     assert False, f'receive from peer={peer_addr} wrong packet={roce_pkt.show(dump=True)}'
                logging.debug(
                    f"received packet No. {idx + 1} for QP={dqpn} from IP={peer_addr}, \
                        total {npkt} packets expected"
                )
                # TODO: handle head verification, wrong QPN
                assert dqpn in self.qp_dict, f"wrong QPN={dqpn} in received packet"
                local_qp = self.qp_dict[dqpn]
                opcodes.append(local_qp.recv_pkt(roce_pkt, retry_handler))
            logging.debug(f"received {npkt} RoCE packets")
            return opcodes
