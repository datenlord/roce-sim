import argparse
import logging
import socket
import struct
from roce_enum import *
from roce_util import Util
from roce_v2 import *

POS_IN_MR = 8
MR_SIZE = 1024
MSG_SIZE = MR_SIZE - POS_IN_MR

SRC_PORT = 9527

# S_RKEY = '00000208'
# S_QPN = '00000011'
S_LID = 0
# S_GID = '00000000000000000000ffffc0a87aee'
S_MAX_RD_ATOMIC = 10
S_MIN_RNR_TIMER = 1  # 0.01 usec
S_PSN = 1000
S_RETRY_CNT = 3
S_RNR_RETRY = 3
S_TIMEOUT = 17  # 536.9 msec
S_VA = "000056482bb76120"

ReceiveReady = 0
SendSize = 1
ReadSize = 2
WriteSize = 3
WriteImm = 4
WriteDone = 5
AtomicReady = 6
AtomicDone = 7
ReadFailSize = 8
SendOverSize = 9
SendRetryRNR = 10
SendRetrySeq = 11

parser = argparse.ArgumentParser(description="Input server IP")
parser.add_argument("-s", action="store", dest="src_ip")
arg_res = parser.parse_args()

logging.basicConfig(level=logging.INFO)

# Build RoCE data structure
roce = RoCEv2()
pd = roce.alloc_pd()
cq = roce.create_cq()
qp = roce.create_qp(
    pd=pd,
    cq=cq,
    access_flags=ACCESS_FLAGS.LOCAL_WRITE
    | ACCESS_FLAGS.REMOTE_WRITE
    | ACCESS_FLAGS.REMOTE_READ
    | ACCESS_FLAGS.REMOTE_ATOMIC,
)
mr = pd.reg_mr(
    va=int(S_VA, 16),
    length=MR_SIZE,
    access_flags=ACCESS_FLAGS.LOCAL_WRITE
    | ACCESS_FLAGS.REMOTE_WRITE
    | ACCESS_FLAGS.REMOTE_READ
    | ACCESS_FLAGS.REMOTE_ATOMIC
    | ACCESS_FLAGS.ZERO_BASED,
)
mr.write(byte_data=b"000000001234567890ABCEDFGHIJKLMNOPQRSTUVWXYZ")

# Wait for connection
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_bind_addr = ("0.0.0.0", SRC_PORT)
udp_sock.bind(server_bind_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# logging.debug(struct.unpack('<c', exch_data))
udp_sock.sendto(struct.pack("c", b"2"), peer_addr)

# Send metadata
src_retry_cnt = "{:02x}".format(S_RETRY_CNT)
src_rnr_retry = "{:02x}".format(S_RNR_RETRY)
src_max_rd_atomic = "{:02x}".format(S_MAX_RD_ATOMIC)
src_rnr_timer = "{:02x}".format(S_MIN_RNR_TIMER)
src_timeout = "{:02x}".format(S_TIMEOUT)
src_start_psn = "{:08x}".format(S_PSN)
src_va = "{:016x}".format(POS_IN_MR)
src_rkey = "{:08x}".format(mr.rkey())
src_qpn = "{:08x}".format(qp.qpn())
src_lid = "{:02x}".format(S_LID)
src_gid = "{0:0>32}".format("ffff" + socket.inet_aton(arg_res.src_ip).hex())
# server_metadata = (
#     src_retry_cnt
#     + src_rnr_retry
#     + src_max_rd_atomic
#     + src_rnr_timer
#     + src_timeout
#     + src_start_psn
#     + src_va
#     + src_rkey
#     + src_qpn
#     + src_lid
#     + src_gid
# )
# udp_sock.sendto(bytes.fromhex(server_metadata), peer_addr)
server_metadata = struct.pack(
    "!BBBBBIQIIB16s",
    S_RETRY_CNT,
    S_RNR_RETRY,
    S_MAX_RD_ATOMIC,
    S_MIN_RNR_TIMER,
    S_TIMEOUT,
    S_PSN,
    POS_IN_MR,
    mr.rkey(),
    qp.qpn(),
    S_LID,
    bytes.fromhex(src_gid),
)
udp_sock.sendto(server_metadata, peer_addr)
# Recive metadata
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("!BBBBBIQIIB16s", exch_data)
(
    dst_retry_cnt,
    dst_rnr_retry,
    dst_max_rd_atomic,
    dst_rnr_timer,
    dst_timeout,
    dst_start_psn,
    dst_va,
    dst_rkey,
    dst_qpn,
    dst_lid,
    dst_gid,
) = parsed_fields
# Client should follow server settings
(
    src_max_rd_atomic_num,
    src_rnr_timer_num,
    src_timeout_num,
    src_retry_cnt_num,
    src_rnr_retry_num,
) = struct.unpack(
    "!BBBBB",
    bytes.fromhex(
        src_max_rd_atomic + src_rnr_timer + src_timeout + src_retry_cnt + src_rnr_retry
    ),
)
qp.modify_qp(
    qps=QPS.RTR,
    dgid=dst_gid,
    dst_qpn=dst_qpn,  # dqpn should be integer
    max_dest_rd_atomic=src_max_rd_atomic_num,
    min_rnr_timer=src_rnr_timer_num,
    rq_psn=dst_start_psn,
)

# Exchange receive ready
udp_sock.sendto(struct.pack("<i", ReceiveReady), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)

qp.modify_qp(
    qps=QPS.RTS,
    sq_psn=S_PSN,
    timeout=src_timeout_num,
    retry_cnt=src_retry_cnt_num,
    rnr_retry=src_rnr_retry_num,
)
logging.debug(
    f"qp.dip()={qp.dip()}, qp.rq.min_rnr_timer={qp.min_rnr_timer}, dst_rnr_timer={dst_rnr_timer}"
)

case_no = 0

###############################################################################
# Case 1: server send data to client, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", SendSize, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
_ = struct.unpack("<iq", exch_data)

# RoCE send and ack
sg = SG(pos_in_mr=POS_IN_MR, length=send_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.SEND_WITH_IMM,
    sgl=sg,
    send_flags=SEND_FLAGS.SIGNALED,
    imm_data_or_inv_rkey=0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 2: client read data from server, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange read size
read_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", ReadSize, read_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<iq", exch_data)
_, read_size = parsed_fields

# RoCE read and ack
mr.write(byte_data=b"00000000abcdefghijklmnopqrstuvwxyz")
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is None, "cqe should not exist"

###############################################################################
# Case 3: client write data to server, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write size
udp_sock.sendto(struct.pack("<iq", WriteSize, -1), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<iq", exch_data)
_, write_size = parsed_fields

# RoCE write and ack
write_req_pkt_num = Util.compute_wr_pkt_num(write_size, qp.mtu())
roce.recv_pkts(write_req_pkt_num)
cqe = qp.poll_cq()
assert cqe is None, "cqe should not exist"

###############################################################################
# Case 4: server write imm with no data to client, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write imm
udp_sock.sendto(struct.pack("<i", WriteImm), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
_ = struct.unpack("<i", exch_data)

# RoCE write imm and ack
sg = SG(pos_in_mr=0, length=0, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.RDMA_WRITE_WITH_IMM,
    sgl=sg,
    # rmt_va = dst_va,
    # rkey = dst_rkey,
    send_flags=SEND_FLAGS.SIGNALED,
    imm_data_or_inv_rkey=0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 0
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.SUCCESS

# Exchange write done
udp_sock.sendto(struct.pack("<i", WriteDone), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
_ = struct.unpack("<i", exch_data)

###############################################################################
# Case 5: server write imm with no data to client, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange atomic ready
udp_sock.sendto(struct.pack("<i", AtomicReady), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
_ = struct.unpack("<i", exch_data)

# RoCE atomic and ack
sg = SG(pos_in_mr=POS_IN_MR, length=8, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.ATOMIC_CMP_AND_SWP,
    sgl=sg,
    rmt_va=dst_va,
    rkey=dst_rkey,
    compare_add=0,
    swap=1,
)
qp.post_send(sr)
qp.process_one_sr()
# TODO: soft-roce failed to ack atomic operation
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.COMP_SWAP
assert cqe.status() == WC_STATUS.SUCCESS

# Exchange atomic done
udp_sock.sendto(struct.pack("<i", AtomicDone), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
logging.debug(struct.unpack("<i", exch_data))

# Save next PSN
sq_psn = qp.npsn()
rq_psn = qp.epsn()

###############################################################################
# Case 6: client read with wrong rkey and NAK remote access error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Clear CQ
cq.clear()
# Reset QP state
qp.modify_qp(qps=QPS.RTS, sq_psn=sq_psn, rq_psn=rq_psn)
# Exchange read size
udp_sock.sendto(struct.pack("<iq", ReadFailSize, MSG_SIZE), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<iq", exch_data)
_, read_size = parsed_fields

# RoCE read and ack
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is None, "cqe should not exist"
assert qp.status() == QPS.ERR

###############################################################################
# Case 7: client send oversize data to server and NAK invalid request error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

zero_mr_size = 0
zero_mr = pd.reg_mr(
    va=int(S_VA, 16),
    length=zero_mr_size,
    access_flags=ACCESS_FLAGS.LOCAL_WRITE
    | ACCESS_FLAGS.REMOTE_WRITE
    | ACCESS_FLAGS.REMOTE_READ
    | ACCESS_FLAGS.REMOTE_ATOMIC
    | ACCESS_FLAGS.ZERO_BASED,
)
assert zero_mr.len() == zero_mr_size

# Clear CQ
cq.clear()
# Reset QP state
qp.modify_qp(qps=QPS.RTS, sq_psn=sq_psn, rq_psn=rq_psn)
# Post receive
sg = SG(pos_in_mr=0, length=zero_mr.len(), lkey=zero_mr.lkey())
rr = RecvWR(sgl=sg)
qp.post_recv(rr)

# Exchange send size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendOverSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields

# RoCE send and ack
assert zero_mr_size < send_size
send_req_pkt_num = Util.compute_wr_pkt_num(send_size, qp.mtu())
# Receive the first send request and response NAK invalid request
roce.recv_pkts(1)
print(f"send_size={send_size}, send_req_pkt_num={send_req_pkt_num}")
roce.clear_remaining_pkts(send_req_pkt_num - 1)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == zero_mr_size
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.REM_INV_REQ_ERR
assert qp.status() == QPS.ERR

###############################################################################
# Case 8: server send data to client and exceed the largest RNR retry limit
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Clear CQ
cq.clear()
# Reset QP state
qp.modify_qp(qps=QPS.RTS, sq_psn=sq_psn, rq_psn=rq_psn)
# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", SendRetryRNR, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
_ = struct.unpack("<iq", exch_data)

# RoCE send and ack
sg = SG(pos_in_mr=POS_IN_MR, length=send_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.SEND_WITH_IMM,
    sgl=sg,
    send_flags=SEND_FLAGS.SIGNALED,
    imm_data_or_inv_rkey=0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(npkt=qp.rnr_retry)  # Retry 3 times and failed
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.RNR_RETRY_EXC_ERR
assert qp.status() == QPS.ERR

###############################################################################
# Case 9: client send data to server and exceed the smallest RNR retry limit
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Clear CQ
cq.clear()
# Reset QP state
qp.modify_qp(
    qps=QPS.RTS,
    sq_psn=sq_psn,
    rq_psn=rq_psn,
    min_rnr_timer=1,  # Smallest RNR wait timer 0.01ms
)

# Exchange send size
udp_sock.sendto(struct.pack("<iq", SendRetrySeq, -1), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields

# RoCE send and RNR NAK
send_req_pkt_num = Util.compute_wr_pkt_num(send_size, qp.mtu())
total_retry_cnt = None
if qp.rnr_retry > qp.retry_cnt:
    # In this case, the retry limit is retry_cnt
    # Total retry count is first normal try + retry_cnt + retry_cnt - 1
    total_retry_cnt = 1 + qp.retry_cnt + qp.retry_cnt - 1
else:
    # In this case, the retry limit is rnr_retry
    # Total retry count is first normal try + rnr_retry - 1 + rnr_retry -1
    total_retry_cnt = 1 + qp.rnr_retry - 1 + qp.rnr_retry - 1
roce.recv_pkts(npkt=total_retry_cnt * send_req_pkt_num)
cqe = qp.poll_cq()
assert cqe is None, "cqe should not exist"
assert qp.status() == QPS.RTS


udp_sock.close()
