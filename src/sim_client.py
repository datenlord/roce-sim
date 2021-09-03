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
DST_PORT = 9527

C_LID = 0
C_MAX_RD_ATOMIC = 10
C_MIN_RNR_TIMER = 1  # 0.01 usec
C_PSN = 10000
C_RETRY_CNT = 3
C_RNR_RETRY = 3
C_TIMEOUT = 17  # 536.9 msec
C_VA = "000056482bb76120"

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

parser = argparse.ArgumentParser(description="Input server IP and client IP")
parser.add_argument("-s", action="store", dest="src_ip")
parser.add_argument("-d", action="store", dest="dst_ip")
arg_res = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)

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
    va=int(C_VA, 16),
    length=MR_SIZE,
    access_flags=ACCESS_FLAGS.LOCAL_WRITE
    | ACCESS_FLAGS.REMOTE_WRITE
    | ACCESS_FLAGS.REMOTE_READ
    | ACCESS_FLAGS.REMOTE_ATOMIC
    | ACCESS_FLAGS.ZERO_BASED,
)
mr.write(byte_data=b"000000001234567890ABCEDFGHIJKLMNOPQRSTUVWXYZ")

# Connect to server
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_bind_addr = ("0.0.0.0", SRC_PORT)
udp_sock.bind(client_bind_addr)
srv_addr = (arg_res.dst_ip, DST_PORT)
udp_sock.sendto(struct.pack("c", b"1"), srv_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)

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
logging.debug(f"received server metadata: {parsed_fields}")
# Send metadata
src_retry_cnt = "{:02x}".format(C_RETRY_CNT)
src_rnr_retry = "{:02x}".format(C_RNR_RETRY)
src_max_rd_atomic = "{:02x}".format(C_MAX_RD_ATOMIC)
src_rnr_timer = "{:02x}".format(C_MIN_RNR_TIMER)
src_timeout = "{:02x}".format(C_TIMEOUT)
src_start_psn = "{:08x}".format(C_PSN)
src_va = "{:016x}".format(POS_IN_MR)
src_rkey = "{:08x}".format(mr.rkey())
src_qpn = "{:08x}".format(qp.qpn())
src_lid = "{:02x}".format(C_LID)
src_gid = "{0:0>32}".format("ffff" + socket.inet_aton(arg_res.src_ip).hex())
# client_metadata = (
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
# udp_sock.sendto(bytes.fromhex(client_metadata), peer_addr)
client_metadata = struct.pack(
    "!BBBBBIQIIB16s",
    C_RETRY_CNT,
    C_RNR_RETRY,
    C_MAX_RD_ATOMIC,
    C_MIN_RNR_TIMER,
    C_TIMEOUT,
    C_PSN,
    POS_IN_MR,
    mr.rkey(),
    qp.qpn(),
    C_LID,
    bytes.fromhex(src_gid),
)
udp_sock.sendto(client_metadata, peer_addr)

# Setup QP, post receive
sg = SG(pos_in_mr=POS_IN_MR, length=mr.len() - POS_IN_MR, lkey=mr.lkey())
rr = RecvWR(sgl=sg)
# Client should follow server settings
qp.modify_qp(
    qps=QPS.RTR,
    dgid=dst_gid,
    dst_qpn=dst_qpn,  # dqpn should be integer
    max_dest_rd_atomic=dst_max_rd_atomic,
    min_rnr_timer=dst_rnr_timer,
    rq_psn=dst_start_psn,
)
qp.post_recv(rr)

# Exchange receive ready
udp_sock.sendto(struct.pack("<i", ReceiveReady), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
logging.debug(struct.unpack("<i", exch_data))

qp.modify_qp(
    qps=QPS.RTS,
    sq_psn=C_PSN,
    timeout=dst_timeout,
    retry_cnt=dst_retry_cnt,
    rnr_retry=dst_rnr_retry,
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
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields
logging.debug(f"send_size={send_size}")

# RoCE send and ack
send_req_pkt_num = Util.compute_wr_pkt_num(send_size, qp.mtu())
roce.recv_pkts(send_req_pkt_num)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == send_size
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 2: client read data from server, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange read size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", ReadSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, read_size = parsed_fields
logging.debug(f"parsed_fields={parsed_fields}")

# RoCE read and ack
sg = SG(pos_in_mr=POS_IN_MR, length=read_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.RDMA_READ,
    sgl=sg,
    rmt_va=dst_va,
    rkey=dst_rkey,
)
qp.post_send(sr)
read_resp_pkt_num = Util.compute_wr_pkt_num(read_size, qp.mtu())
qp.process_one_sr()
roce.recv_pkts(read_resp_pkt_num)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == read_size
assert cqe.op() == WC_OPCODE.RDMA_READ
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 3: client write data to server, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write size
write_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", WriteSize, write_size), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
logging.debug(f"parsed_fields={parsed_fields}")

# RoCE write and ack
sg = SG(pos_in_mr=POS_IN_MR, length=write_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.RDMA_WRITE,
    sgl=sg,
    rmt_va=dst_va,
    rkey=dst_rkey,
    send_flags=SEND_FLAGS.SIGNALED,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 4: server write imm with no data to client, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", WriteImm), peer_addr)
parsed_fields = struct.unpack("<i", exch_data)
logging.debug(f"parsed_fields={parsed_fields}")

# RoCE write imm and ack
qp.post_recv(rr)
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 0
assert cqe.op() == WC_OPCODE.RECV_RDMA_WITH_IMM
assert cqe.status() == WC_STATUS.SUCCESS
assert cqe.imm_data_or_inv_rkey() is not None

# Exchange write done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", WriteDone), peer_addr)
parsed_fields = struct.unpack("<i", exch_data)
logging.debug(f"parsed_fields={parsed_fields}")

###############################################################################
# Case 5: server write imm with no data to client, normal case
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange atomic ready
mr.write(b"\x01\x00\x00\x00\x00\x00\x00\x00", addr=8)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", AtomicReady), peer_addr)
logging.debug(struct.unpack("<i", exch_data))

# RoCE atomic and ack
roce.recv_pkts(1)
logging.debug(mr.read(addr=0, size=24))

# Exchange atomic done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", AtomicDone), peer_addr)
logging.debug(struct.unpack("<i", exch_data))

# Save next PSN
sq_psn = qp.npsn()
rq_psn = qp.epsn()

###############################################################################
# Case 6: client read with wrong rkey and NAK remote access error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Reset QP status
qp.modify_qp(qps=QPS.RTS, sq_psn=sq_psn, rq_psn=rq_psn)
# Exchange read size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", ReadFailSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, read_size = parsed_fields
logging.debug(f"parsed_fields={parsed_fields}")

# RoCE read and ack
sg = SG(pos_in_mr=POS_IN_MR, length=read_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.RDMA_READ,
    sgl=sg,
    rmt_va=dst_va,
    rkey=0xFFFFFFFF,  # Wrong remote key
)
qp.post_send(sr)
read_resp_pkt_num = Util.compute_wr_pkt_num(read_size, qp.mtu())
qp.process_one_sr()
roce.recv_pkts(1)  # Receive only 1 NAK packet
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == read_size
assert cqe.op() == WC_OPCODE.RDMA_READ
assert cqe.status() == WC_STATUS.REM_ACCESS_ERR
assert qp.status() == QPS.ERR

###############################################################################
# Case 7: client send oversize data to server and NAK invalid request error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Reset QP state
qp.modify_qp(qps=QPS.RTS, sq_psn=sq_psn, rq_psn=rq_psn)
# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", SendOverSize, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
logging.debug(struct.unpack("<iq", exch_data))

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
assert cqe.status() == WC_STATUS.REM_INV_REQ_ERR
assert qp.status() == QPS.ERR

###############################################################################
# Case 8: server send data to client and exceed the largest RNR retry limit
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Reset QP state
qp.modify_qp(
    qps=QPS.RTS,
    sq_psn=sq_psn,
    rq_psn=rq_psn,
    min_rnr_timer=0,  # Largest RNR wait timer 655.36ms
)
# Exchange send size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendRetryRNR, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields
logging.debug(struct.unpack("<iq", exch_data))

# RoCE send and RNR NAK
send_req_pkt_num = Util.compute_wr_pkt_num(send_size, qp.mtu())
roce.recv_pkts(npkt=qp.rnr_retry * send_req_pkt_num)
cqe = qp.poll_cq()
assert cqe is None, "cqe should not exist"
assert qp.status() == QPS.RTS

###############################################################################
# Case 9: client send data to server and exceed the smallest RNR retry limit
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Clear CQ
cq.clear()
# Reset QP state
qp.modify_qp(qps=QPS.RTS, sq_psn=sq_psn, rq_psn=rq_psn)
# Exchange send size
send_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendRetrySeq, send_size), peer_addr)
logging.debug(struct.unpack("<iq", exch_data))

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
total_retry_cnt = None  # TODO: find out how many response packets
if qp.rnr_retry > qp.retry_cnt:
    total_retry_cnt = 1 + qp.retry_cnt + qp.retry_cnt - 1
else:
    total_retry_cnt = 1 + qp.rnr_retry - 1 + qp.rnr_retry - 1
roce.recv_pkts(npkt=total_retry_cnt)
roce.clear_remaining_pkts(npkt=total_retry_cnt)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.RNR_RETRY_EXC_ERR
assert qp.status() == QPS.ERR


udp_sock.close()
