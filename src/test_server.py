import argparse
import logging
import socket
import struct
from roce_enum import *
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
S_PSN = 10000
S_RETRY_CNT = 3
S_RNR_RETRY = 3
S_TIMEOUT = 17  # 536.9 msec
S_VA = "000056482bb76120"

ReceiveReady = 0
SendImm = 1
WriteImm = 2
ReadZero = 3
SendImmSize = 4
AtomicReady = 5
SendNoAck = 6
WriteImmSize = 7
SendSize = 8
ReadSize = 9
SendInv = 10
SendDone = 11
WriteRetrySeq = 12

parser = argparse.ArgumentParser(description="Input server IP")
parser.add_argument("-s", action="store", dest="src_ip")
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
server_metadata = (
    src_retry_cnt
    + src_rnr_retry
    + src_max_rd_atomic
    + src_rnr_timer
    + src_timeout
    + src_start_psn
    + src_va
    + src_rkey
    + src_qpn
    + src_lid
    + src_gid
)
# server_metadata = struct.pack('!BBBBBIQIIB16s',
#     S_RETRY_CNT,
#     S_RNR_RETRY,
#     S_MAX_RD_ATOMIC,
#     S_MIN_RNR_TIMER,
#     S_TIMEOUT,
#     S_PSN,
#     POS_IN_MR,
#     mr.rkey(),
#     qp.qpn(),
#     S_LID,
#     src_gid,
# )
udp_sock.sendto(bytes.fromhex(server_metadata), peer_addr)
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
logging.debug(f"received client metadata: {parsed_fields}")

# Setup QP, post receive
sg = SG(pos_in_mr=POS_IN_MR, length=mr.len() - POS_IN_MR, lkey=mr.lkey())
rr = RecvWR(sgl=sg)
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
# logging.debug(struct.unpack('<i', exch_data))

qp.modify_qp(
    qps=QPS.RTS,
    sq_psn=S_PSN,
    timeout=dst_timeout,
    retry_cnt=dst_retry_cnt,
    rnr_retry=dst_rnr_retry,
)
logging.debug(f"qp.rq.min_rnr_timer={qp.min_rnr_timer}, dst_rnr_timer={dst_rnr_timer}")

case_no = 0

###############################################################################
# Case 1: client send zero data with imm to server and retry due to NAK sequence error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send zero with imm
udp_sock.sendto(struct.pack("<i", SendImm), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# logging.debug(struct.unpack('<i', exch_data))

# RoCE send zero with imm and ack
roce.recv_pkts(
    2
)  # Receive two send requests both with wrong PSN, the second one should be discarded
cqe = qp.poll_cq()
assert cqe is None, "NAK sequence error response to send and should not have CQE"
roce.recv_pkts(1)  # Receive send request match ePSN
cqe = qp.poll_cq()
assert cqe is not None, "send with imm and signaled should have CQE in responder"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 0
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS
assert cqe.imm_data_or_inv_rkey() is not None

###############################################################################
# Case 2: client write zero data with imm to server and retry due to RNR
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write zero with imm
udp_sock.sendto(struct.pack("<i", WriteImm), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<i", exch_data)
# logging.debug(parsed_fields)

# RoCE write zero with imm and ack
roce.recv_pkts(1)  # Receive write with imm but return RNR NAK
roce.recv_pkts(1)  # Receive write with imm again but no response this time
cqe = qp.poll_cq()
assert cqe is None, "RNR NAK response to write and should not have CQE"
sg = SG(pos_in_mr=0, length=0, lkey=0)
rr = RecvWR(sgl=sg)
qp.post_recv(rr)
roce.recv_pkts(1)  # Receive write with imm again
cqe = qp.poll_cq()
assert cqe is not None, "write with imm should have CQE in responder"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 0
assert cqe.op() == WC_OPCODE.RECV_RDMA_WITH_IMM
assert cqe.status() == WC_STATUS.SUCCESS
assert cqe.imm_data_or_inv_rkey() is not None

###############################################################################
# Case 3: client read zero data from server
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange read zero
udp_sock.sendto(struct.pack("<i", ReadZero), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<i", exch_data)
# logging.debug(parsed_fields)

# RoCE read zero
roce.recv_pkts(1)  # Receive read ack
cqe = qp.poll_cq()
assert cqe is None, "read should not have CQE in responder"

###############################################################################
# Case 4: server send to client without requesting ACK and retry due to NAK sequence error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", SendImmSize, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# logging.debug(struct.unpack('<iq', exch_data))

# RoCE send and rnr retry without ack
sg = SG(pos_in_mr=POS_IN_MR, length=send_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.SEND_WITH_IMM,
    sgl=sg,
    # send_flags = SEND_FLAGS.SIGNALED, No need to ACK
    imm_data_or_inv_rkey=0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
# RoCE atomic and timeout
sg = SG(pos_in_mr=POS_IN_MR, length=8, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.ATOMIC_FETCH_AND_ADD,
    sgl=sg,
    rmt_va=dst_va,
    rkey=dst_rkey,
    compare_add=1,
    # swap = 1,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)  # Receive NAK seq err
cqe = qp.poll_cq()
assert (
    cqe is None
), "send without signaled should not have CQE in requester before implicit ACK"

roce.recv_pkts(1)  # Receive atomic ACK
cqe = qp.poll_cq()  # This CQE is for previous send operation
assert (
    cqe is not None
), "send without signaled should have CQE in responder after implicit ACK"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == send_size
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS

cqe = qp.poll_cq()
assert cqe is not None, "atomic should have CQE in requester"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 8
assert cqe.op() == WC_OPCODE.FETCH_ADD
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 5: client send atomic request to server
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange atomic ready
udp_sock.sendto(struct.pack("<i", AtomicReady), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# logging.debug(struct.unpack('<i', exch_data))

# RoCE atomic
roce.recv_pkts(1)  # Receive atomic ack
cqe = qp.poll_cq()
assert cqe is None, "atomic should not have CQE in responder"

###############################################################################
# Case 6: client send, atomic and write request to server and retry by implicit NAK
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", SendNoAck, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# logging.debug(struct.unpack('<iq', exch_data))

# RoCE send and rnr retry without ack
sg = SG(pos_in_mr=POS_IN_MR, length=send_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.SEND,
    sgl=sg,
    # send_flags = SEND_FLAGS.SIGNALED, No need to ACK
)
qp.post_send(sr)
qp.process_one_sr()

# # Exchange atomic ready
# udp_sock.sendto(struct.pack("<i", AtomicDone), peer_addr)
# exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# # logging.debug(struct.unpack('<i', exch_data))

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
sg = SG(pos_in_mr=POS_IN_MR, length=0, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.RDMA_WRITE,
    sgl=sg,
    # rmt_va = dst_va,
    # rkey = dst_rkey,
    send_flags=SEND_FLAGS.SIGNALED,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(
    1
)  # Receive the ACK to the last write operation, implicit NAK to previous atomic operation

cqe = qp.poll_cq()  # This CQE is for previous send operation
assert (
    cqe is not None
), "send without signaled should have CQE in responder after implicit ACK"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == send_size
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS

roce.recv_pkts(2)  # Receive two ACK responses to atomic and write operations

cqe = qp.poll_cq()  # This CQE is for the atomic operation
assert cqe is not None, "atomic should have CQE in requester"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 8
assert cqe.op() == WC_OPCODE.COMP_SWAP
assert cqe.status() == WC_STATUS.SUCCESS

cqe = qp.poll_cq()  # This CQE is for the write operation
assert cqe is not None, "write should have CQE in requester"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 7: server write with imm to client and retry the last write request due to RNR NAK
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write imm size
udp_sock.sendto(struct.pack("<iq", WriteImmSize, -1), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<iq", exch_data)
_, write_size = parsed_fields
# logging.debug(parsed_fields)

# RoCE write imm and ack
sg = SG(pos_in_mr=POS_IN_MR, length=write_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.RDMA_WRITE_WITH_IMM,
    sgl=sg,
    rmt_va=dst_va,
    rkey=dst_rkey,
    send_flags=SEND_FLAGS.SIGNALED,
    imm_data_or_inv_rkey=0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(2)  # Receive rnr nak and ack
cqe = qp.poll_cq()
assert cqe is not None, "write with imm should have CQE in responder"
logging.debug(f"cqe op={cqe.op()}, status={cqe.status()}")
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 8: server send to client without requesting ACK and retry due to NAK RNR
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", SendSize, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# logging.debug(struct.unpack('<iq', exch_data))

# RoCE send and rnr retry without ack
sg = SG(pos_in_mr=POS_IN_MR, length=send_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.SEND_WITH_IMM,
    sgl=sg,
    # send_flags = SEND_FLAGS.SIGNALED, No need to ACK
    imm_data_or_inv_rkey=0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)  # Receive RNR NAK
cqe = qp.poll_cq()
assert (
    cqe is None
), "send without signaled should not have CQE in requester before implicit ACK"

###############################################################################
# Case 9: server read from client with retried request due to NAK sequence error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange read size
udp_sock.sendto(struct.pack("<iq", ReadSize, -1), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<iq", exch_data)
_, read_size = parsed_fields
# logging.debug(parsed_fields)

# RoCE read and ack
sg = SG(pos_in_mr=POS_IN_MR, length=read_size, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.RDMA_READ,
    sgl=sg,
    rmt_va=dst_va,
    rkey=dst_rkey,
)
qp.post_send(sr)
read_resp_pkt_num = math.ceil(read_size / roce.mtu()) if read_size > 0 else 1
qp.process_one_sr()
# Receive retried read requests each retried once,
# and one read response with wrong opcode sequence
roce.recv_pkts(read_resp_pkt_num * 2 + 1)
# First CQE is for previous send operation
cqe = qp.poll_cq()
assert (
    cqe is not None
), "send without signaled should have CQE in requester after implicit ACK"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == send_size
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS
# Second CQE is for the read operation
cqe = qp.poll_cq()
assert cqe is not None, "read should have CQE in requester after received response"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
# logging.debug(f'cqe.len()={cqe.len()} != sg.len()={sg.len()}, read_size={read_size}, cqe.op()={cqe.op()}')
assert cqe.len() == read_size
assert cqe.op() == WC_OPCODE.RDMA_READ
assert cqe.status() == WC_STATUS.SUCCESS

###############################################################################
# Case 10: server send with inv and atomic to client and retry due to timeout
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack("<iq", SendInv, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# logging.debug(struct.unpack('<iq', exch_data))

# RoCE atomic and timeout
sg = SG(pos_in_mr=POS_IN_MR, length=8, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.ATOMIC_FETCH_AND_ADD,
    sgl=sg,
    rmt_va=dst_va,
    rkey=dst_rkey,
    compare_add=1,
    # swap = 1,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(npkt=0)  # Wait for timeout and then retry
# RoCE send with inv and ack both
sg = SG(pos_in_mr=POS_IN_MR, length=0, lkey=mr.lkey())
sr = SendWR(
    opcode=WR_OPCODE.SEND_WITH_INV,
    sgl=sg,
    send_flags=SEND_FLAGS.SIGNALED,
    imm_data_or_inv_rkey=dst_rkey,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(2)  # Receive both atomic and send ACK

cqe = qp.poll_cq()
assert cqe is not None, "atomic should have CQE in requester"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 8
assert cqe.op() == WC_OPCODE.FETCH_ADD
assert cqe.status() == WC_STATUS.SUCCESS

cqe = qp.poll_cq()
assert cqe is not None, "send with inv and signaled should have CQE in requester"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 0
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS

# Exchange send done
udp_sock.sendto(struct.pack("<i", SendDone), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<i", exch_data)
# logging.debug(parsed_fields)

###############################################################################
# Case 11: server write to client retry due to wrong PSN and exceed the retry limit
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write size
write_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", WriteRetrySeq, write_size), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
logging.debug(f"parsed_fields={parsed_fields}")

# RoCE write and retry
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
roce.recv_pkts(qp.retry_cnt)
cqe = qp.poll_cq()
assert cqe is not None, "cqe should exist"
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.RETRY_EXC_ERR
assert qp.status() == QPS.ERR


udp_sock.close()
