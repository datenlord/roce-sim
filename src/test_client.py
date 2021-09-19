import argparse
import logging
import math
import socket
import struct
import time

from roce import AETH, AtomicAckETH, AtomicETH, BTH, ImmDt, RETH
from roce_enum import RC
from roce_util import Util
from scapy.all import *

POS_IN_MR = 8
MR_SIZE = 1024
PMTU = 256
MSG_SIZE = MR_SIZE - POS_IN_MR

# DST_IP = '192.168.122.238'
ROCE_PORT = 4791
DST_PORT = 9527
SRC_PORT = 6543
UDP_BUF_SIZE = 2048

# Parameter to exchange with server to setup QP
# C_GID = '00000000000000000000ffffc0a87abe'
C_LID = 0
C_MAX_RD_ATOMIC = 10
C_MIN_RNR_TIMER = 0  # 655_360 usec
C_PSN = 1000
C_QPN = 17
C_RETRY_CNT = 3
C_RKEY = 208
C_RNR_RETRY = 3
C_TIMEOUT = 17  # 536.9 msec
C_VA = "0000556acaa2ea50"

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

src_cpsn = 0  # for SQ
src_npsn = 0  # for SQ
src_epsn = 0  # for RQ

parser = argparse.ArgumentParser(description="Input server IP and client IP")
parser.add_argument("-s", action="store", dest="src_ip")
parser.add_argument("-d", action="store", dest="dst_ip")
arg_res = parser.parse_args()

# RoCE socket
roce_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
roce_bind_addr = ("0.0.0.0", ROCE_PORT)
roce_sock.bind(roce_bind_addr)

# Connect to server
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_bind_addr = ("0.0.0.0", SRC_PORT)
udp_sock.bind(client_bind_addr)
srv_addr = (arg_res.dst_ip, DST_PORT)
udp_sock.sendto(struct.pack("c", b"1"), srv_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)

# Receive metadata
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
logging.debug(f"received server metadata={parsed_fields}")
# Send metadata
src_retry_cnt = "{:02x}".format(C_RETRY_CNT)
src_rnr_retry = "{:02x}".format(C_RNR_RETRY)
src_max_rd_atomic = "{:02x}".format(C_MAX_RD_ATOMIC)
src_rnr_timer = "{:02x}".format(C_MIN_RNR_TIMER)
src_timeout = "{:02x}".format(C_TIMEOUT)
src_start_psn = "{:08x}".format(C_PSN)
src_va = "{:016x}".format(POS_IN_MR)
src_rkey = "{:08x}".format(C_RKEY)
src_qpn = "{:08x}".format(C_QPN)
src_lid = "{:02x}".format(C_LID)
src_gid = "{0:0>32}".format("ffff" + socket.inet_aton(arg_res.src_ip).hex())
client_metadata = (
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
udp_sock.sendto(bytes.fromhex(client_metadata), peer_addr)
# Update SQ and RQ start PSN
src_cpsn = C_PSN  # for SQ
src_npsn = src_cpsn  # for SQ
src_epsn = dst_start_psn  # for RQ

# Exchange receive ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", ReceiveReady), peer_addr)
logging.debug(struct.unpack("<i", exch_data))

case_no = 0

###############################################################################
# Case 1: client send zero data with imm to server and retry due to NAK sequence error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", SendImm), peer_addr)
_ = struct.unpack("<i", exch_data)

# RoCE send imm and ack
src_npsn = src_cpsn + 1
wrong_psn = src_npsn + 2
send_bth = BTH(
    opcode=RC.SEND_ONLY_WITH_IMMEDIATE,
    psn=wrong_psn,
    dqpn=dst_qpn,
    ackreq=True,
)
send_imm_data = ImmDt(data=1234)
send_req = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / send_bth
    / send_imm_data
)
send_req.show()
send(send_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
seq_nak_resp = BTH(roce_bytes)
assert seq_nak_resp[BTH].psn == src_cpsn, "responder ePSN not match requester cPSN"
assert (
    seq_nak_resp[BTH].opcode == RC.ACKNOWLEDGE
    and seq_nak_resp[AETH].code == 3
    and seq_nak_resp[AETH].value == 0
), "send with wrong PSN should receive NAK sequence error"
send(send_req)  # Send request with wrong PSN again, should have no response
send_req[BTH].psn = src_cpsn
send(send_req)  # Send request with correct PSN, should have response
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
send_resp = BTH(roce_bytes)
send_resp.show()
assert (
    send_resp[BTH].psn == src_npsn - 1
), "send with imm response PSN not match expected"
src_cpsn = src_npsn

###############################################################################
# Case 2: client write zero data with imm to server and retried due to RNR
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", WriteImm), peer_addr)
_ = struct.unpack("<i", exch_data)

# RoCE write with imm and RNR retry and ack
src_npsn = src_cpsn + 1
write_imm_bth = BTH(
    opcode=RC.RDMA_WRITE_ONLY_WITH_IMMEDIATE,
    psn=src_cpsn,
    dqpn=dst_qpn,
    ackreq=True,
)
write_imm_reth = RETH(va=dst_va, rkey=dst_rkey, dlen=0)
write_imm_data = ImmDt(data=1234)
write_imm_req = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / write_imm_bth
    / write_imm_reth
    / write_imm_data
)
write_imm_req.show()
send(write_imm_req)  # Send write operation and expect RNR NAK
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
rnr_nak_resp = BTH(roce_bytes)
assert (
    rnr_nak_resp[BTH].opcode == RC.ACKNOWLEDGE and rnr_nak_resp[AETH].code == 1
), "write with imm should have NAK RNR when no receive buffer"
send(write_imm_req)  # Send write again but no response this time
time.sleep(0.65536)  # 0.65536s is the largest RNR timer to wait
send(write_imm_req)  # Wait after RNR timer then send write again and expect ACK
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_imm_resp = BTH(roce_bytes)
write_imm_resp.show()
assert (
    write_imm_resp[BTH].psn == src_npsn - 1
), "write with imm response PSN not match expected"
src_cpsn = src_npsn

###############################################################################
# Case 3: client read zero data from server
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange read zero
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", ReadZero), peer_addr)
_ = struct.unpack("<i", exch_data)

# RoCE read zero and ack
src_npsn = src_cpsn + 1
read_zero_bth = BTH(
    opcode=RC.RDMA_READ_REQUEST,
    psn=src_cpsn,
    dqpn=dst_qpn,
)
read_zero_reth = RETH(va=0, rkey=0, dlen=0)
read_zero_req = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / read_zero_bth
    / read_zero_reth
)
read_zero_req.show()
send(read_zero_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
read_zero_resp = BTH(roce_bytes)
read_zero_resp.show()
assert (
    read_zero_resp[BTH].psn == src_npsn - 1
), "read zero response PSN not match expected"
src_cpsn = src_npsn

###############################################################################
# Case 4: server send to client without requesting ACK and retry due to NAK sequence error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size and RNR NAK
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendImmSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields

# RoCE send and NAK seq err retry without ACK
send_pkt_num = Util.compute_wr_pkt_num(send_size, PMTU)
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    send_req.show()
    assert send_req[BTH].psn == src_epsn + i, "send request PSN not match ePSN"
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
atomic_req.show()
assert (
    atomic_req[BTH].psn == src_epsn + send_pkt_num
), "atomic request PSN not match ePSN"
seq_nak_bth = BTH(
    opcode=RC.ACKNOWLEDGE,
    psn=src_epsn,
    dqpn=dst_qpn,
)
seq_nak_aeth = AETH(code="NAK", value=0, msn=1)
seq_nak_resp = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / seq_nak_bth
    / seq_nak_aeth
)
seq_nak_resp.show()
send(seq_nak_resp)
# RoCE NAK seq err retry send and atomic request
roce_pkts = []
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req[BTH].psn == src_epsn + i, "send request PSN not match ePSN"
    roce_pkts.append(send_req)
    send_req.show()
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
atomic_req.show()
assert (
    atomic_req[BTH].psn == src_epsn + send_pkt_num
), "atomic request PSN not match ePSN"
# RoCE ACK to atomic and implicit ACK to send
atomic_ack_bth = BTH(
    opcode=RC.ATOMIC_ACKNOWLEDGE,
    psn=atomic_req[BTH].psn,
    dqpn=dst_qpn,
)
atomic_ack = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / atomic_ack_bth
    / AETH(code="ACK", value=31, msn=1)
    / AtomicAckETH(orig=0)
)
atomic_ack.show()
send(atomic_ack)
src_epsn += send_pkt_num + 1

###############################################################################
# Case 5: client send atomic request to server
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange atomic ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", AtomicReady), peer_addr)

# RoCE atomic and ack
src_npsn = src_cpsn + 1
atomic_bth = BTH(
    opcode=RC.FETCH_ADD,
    psn=src_cpsn,
    dqpn=dst_qpn,
    ackreq=True,
)
aligned_dst_va = ((dst_va + 7) >> 3) << 3
atomic_eth = AtomicETH(
    va=aligned_dst_va,
    rkey=dst_rkey,
    comp=1,
    swap=0,
)
atomic_req = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / atomic_bth
    / atomic_eth
)
atomic_req.show()
send(atomic_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_resp = BTH(roce_bytes)
atomic_resp.show()
assert atomic_resp[BTH].psn == src_npsn - 1, "atomic response PSN not match expected"
src_cpsn = src_npsn

###############################################################################
# Case 6: client send atomic and write request to server and retry by implicit NAK
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# # Exchange atomic ready
# exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
# udp_sock.sendto(struct.pack("<i", AtomicDone), peer_addr)
# # logging.debug(struct.unpack('<i', exch_data))

# Exchange send size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendNoAck, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields
# RoCE send
send_req_pkt_num = Util.compute_wr_pkt_num(send_size, PMTU)
for i in range(send_req_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    send_req.show()
    assert send_req[BTH].psn == src_epsn + i, "send request PSN not match ePSN"
src_epsn += send_req_pkt_num
# RoCE atomic
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
atomic_req.show()
assert atomic_req[BTH].psn == src_epsn, "atomic request PSN not match ePSN"
# RoCE write zero and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_zero_req = BTH(roce_bytes)
write_zero_req.show()
assert write_zero_req[BTH].psn == src_epsn + 1, "write request PSN not match ePSN"
write_zero_resp_bth = BTH(
    opcode=RC.ACKNOWLEDGE,
    psn=write_zero_req[BTH].psn,
    dqpn=dst_qpn,
)
write_zero_resp = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / write_zero_resp_bth
    / AETH(code="ACK", value=31, msn=1)
)
write_zero_resp.show()
# This response will implicitely NAK both atomic and write operation
send(write_zero_resp)

# RoCE atomic retry
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
atomic_req.show()
assert atomic_req[BTH].psn == src_epsn, "atomic request PSN not match ePSN"
# RoCE write zero retry
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_zero_req = BTH(roce_bytes)
write_zero_req.show()
assert write_zero_req[BTH].psn == src_epsn + 1, "write request PSN not match ePSN"
# RoCE ack to atomic
atomic_ack_bth = BTH(
    opcode=RC.ATOMIC_ACKNOWLEDGE,
    psn=atomic_req[BTH].psn,
    dqpn=dst_qpn,
)
atomic_ack = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / atomic_ack_bth
    / AETH(code="ACK", value=31, msn=1)
    / AtomicAckETH(orig=0)
)
atomic_ack.show()
send(atomic_ack)  # This response will explicitly ACK atomic operation
send(write_zero_resp)  # This response will explicitly ACK write operation

src_epsn += 2

###############################################################################
# Case 7: server write with imm to client and retry the last write request due to RNR NAK
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write imm size
write_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", WriteImmSize, write_size), peer_addr)

# RoCE write imm, rnr retry and ack
write_req_pkt_num = Util.compute_wr_pkt_num(write_size, PMTU)
for i in range(write_req_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    write_req = BTH(roce_bytes)
    assert write_req[BTH].psn == src_epsn + i, "write request PSN not match ePSN"
    write_req.show()
# RNR nak
rnr_nak_bth = BTH(
    opcode=RC.ACKNOWLEDGE,
    psn=src_epsn + write_req_pkt_num - 1,
    dqpn=dst_qpn,
)
rnr_nak_aeth = AETH(code="RNR", value=0, msn=1)
rnr_nak_resp = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / rnr_nak_bth
    / rnr_nak_aeth
)
rnr_nak_resp.show()
send(rnr_nak_resp)
# Retried last write request
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
retry_write_last_req = BTH(roce_bytes)
retry_write_last_req.show()
assert (
    write_req[BTH].psn == src_epsn + write_req_pkt_num - 1
), "retried write request PSN not match ePSN"
write_resp_bth = BTH(
    opcode=RC.ACKNOWLEDGE,
    psn=src_epsn + write_req_pkt_num - 1,
    dqpn=dst_qpn,
)
write_resp = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / write_resp_bth
    / AETH(code="ACK", value=31, msn=1)
)
write_resp.show()
send(write_resp)
src_epsn += write_req_pkt_num

###############################################################################
# Case 8: server send to client without requesting ACK and retry due to NAK RNR
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size and rnr nak
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields

# RoCE send and rnr retry without ack
send_pkt_num = Util.compute_wr_pkt_num(send_size, PMTU)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
send_req = BTH(roce_bytes)
assert send_req[BTH].psn == src_epsn, "send request PSN not match ePSN"
rnr_nak_bth = BTH(
    opcode=RC.ACKNOWLEDGE,
    psn=send_req[BTH].psn,
    dqpn=dst_qpn,
)
rnr_nak_aeth = AETH(code="RNR", value=0, msn=1)
rnr_nak_resp = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / rnr_nak_bth
    / rnr_nak_aeth
)
rnr_nak_resp.show()
send(rnr_nak_resp)
for i in range(send_pkt_num - 1):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req[BTH].psn == src_epsn + i + 1, "send request PSN not match ePSN"
    send_req.show()
# RoCE rnr retry send request
roce_pkts = []
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req[BTH].psn == src_epsn + i, "send request PSN not match ePSN"
    roce_pkts.append(send_req)
    send_req.show()
src_epsn += send_pkt_num

###############################################################################
# Case 9: server read from client with retried request due to NAK sequence error
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange read size
read_str = "RDMA_Read_Operation"
read_size = MSG_SIZE  # len(read_str) #
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", ReadSize, read_size), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, read_size = parsed_fields

# RoCE read, nak seq retry and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
read_req = BTH(roce_bytes)
read_req.show()
assert read_req[BTH].psn == src_epsn, "read request PSN not match ePSN"
read_size = read_req[RETH].dlen
read_resp_pkt_num = Util.compute_wr_pkt_num(read_size, PMTU)
read_aeth = AETH(code="ACK", value=31, msn=1)
nak_seq_aeth = AETH(code="NAK", value=0, msn=1)
if read_size <= PMTU:
    # Ask for retry
    nak_seq_bth = BTH(
        opcode=RC.ACKNOWLEDGE,
        psn=read_req[BTH].psn,
        dqpn=dst_qpn,
    )
    nak_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / nak_seq_bth
        / nak_seq_aeth
    )
    nak_resp.show()
    send(nak_resp)
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    retry_read_req = BTH(roce_bytes)
    assert retry_read_req[BTH].psn == read_req[BTH].psn

    read_resp_bth = BTH(
        opcode=RC.RDMA_READ_RESPONSE_ONLY,
        psn=read_req[BTH].psn,
        dqpn=dst_qpn,
    )
    read_data = struct.pack(f"<{read_size}s", bytearray(read_str, "ascii"))
    read_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / read_resp_bth
        / read_aeth
        / Raw(load=read_data)
    )
    read_resp.show()
    send(read_resp)
else:
    # Retry whole read
    nak_seq_bth = BTH(
        opcode=RC.ACKNOWLEDGE,
        psn=src_epsn,
        dqpn=dst_qpn,
    )
    nak_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / nak_seq_bth
        / nak_seq_aeth
    )
    nak_resp.show()
    send(nak_resp)
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    retry_read_req = BTH(roce_bytes)
    assert retry_read_req[BTH].psn == src_epsn

    read_resp_bth = BTH(
        opcode=RC.RDMA_READ_RESPONSE_FIRST,
        psn=src_epsn,
        dqpn=dst_qpn,
    )
    read_data = struct.pack(f"<{PMTU}s", bytearray(read_str, "ascii"))
    read_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / read_resp_bth
        / read_aeth
        / Raw(load=read_data)
    )
    read_resp.show()
    send(read_resp)

    # Send the last response and retry read from second response packet
    last_read_size = read_size % PMTU
    read_resp_bth = BTH(
        opcode=RC.RDMA_READ_RESPONSE_LAST,
        psn=src_epsn + read_resp_pkt_num - 1,
        dqpn=dst_qpn,
    )
    read_data = struct.pack(f"<{last_read_size}s", bytearray(read_str, "ascii"))
    read_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / read_resp_bth
        / read_aeth
        / Raw(load=read_data)
    )
    read_resp.show()
    send(read_resp)
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    retry_read_req = BTH(roce_bytes)
    assert retry_read_req[BTH].psn == src_epsn + 1

    read_resp_mid_pkt_num = read_resp_pkt_num - 2
    for i in range(read_resp_mid_pkt_num):
        # Retry read from every middle response
        nak_seq_bth = BTH(
            opcode=RC.ACKNOWLEDGE,
            psn=src_epsn + i + 1,
            dqpn=dst_qpn,
        )
        nak_resp = (
            IP(dst=arg_res.dst_ip)
            / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
            / nak_seq_bth
            / nak_seq_aeth
        )
        nak_resp.show()
        send(nak_resp)
        roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
        retry_read_req = BTH(roce_bytes)
        assert retry_read_req[BTH].psn == src_epsn + i + 1

        read_resp_bth = BTH(
            opcode=RC.RDMA_READ_RESPONSE_FIRST,
            psn=src_epsn + i + 1,
            dqpn=dst_qpn,
        )
        read_data = struct.pack(f"<{PMTU}s", bytearray(read_str, "ascii"))
        mid_read_data_len = len(read_data)
        logging.debug(f"mid read data len={mid_read_data_len}")
        read_resp = (
            IP(dst=arg_res.dst_ip)
            / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
            / read_resp_bth
            / read_aeth
            / Raw(load=read_data)
        )
        read_resp.show()
        send(read_resp)

    # Retry read from the last response
    nak_seq_bth = BTH(
        opcode=RC.ACKNOWLEDGE,
        psn=src_epsn + read_resp_mid_pkt_num + 1,
        dqpn=dst_qpn,
    )
    nak_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / nak_seq_bth
        / nak_seq_aeth
    )
    nak_resp.show()
    send(nak_resp)
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    retry_read_req = BTH(roce_bytes)
    assert retry_read_req[BTH].psn == src_epsn + read_resp_mid_pkt_num + 1

    read_resp_bth = BTH(
        opcode=RC.RDMA_READ_RESPONSE_ONLY,
        psn=src_epsn + read_resp_mid_pkt_num + 1,
        dqpn=dst_qpn,
    )
    read_data = struct.pack(f"<{last_read_size}s", bytearray(read_str, "ascii"))
    read_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / read_resp_bth
        / read_aeth
        / Raw(load=read_data)
    )
    read_resp.show()
    send(read_resp)
src_epsn += read_resp_pkt_num

###############################################################################
# Case 10: server send with inv and atomic to client and retry due to timeout
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange send size
send_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendInv, send_size), peer_addr)

# RoCE atomic
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
atomic_req.show()
assert atomic_req[BTH].psn == src_epsn, "atomic request PSN not match ePSN"
# RoCE atomic timeout retry
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
atomic_req.show()
assert atomic_req[BTH].psn == src_epsn, "atomic request PSN not match ePSN"
# RoCE send with inv
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
send_inv_req = BTH(roce_bytes)
send_inv_req.show()
assert send_inv_req[BTH].psn == src_epsn + 1, "send request PSN not match ePSN"
# RoCE ack to atomic
atomic_ack_bth = BTH(
    opcode=RC.ATOMIC_ACKNOWLEDGE,
    psn=atomic_req[BTH].psn,
    dqpn=dst_qpn,
)
atomic_ack = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / atomic_ack_bth
    / AETH(code="ACK", value=31, msn=1)
    / AtomicAckETH(orig=0)
)
atomic_ack.show()
send(atomic_ack)
# RoCE ack to send with inv
send_inv_ack_bth = BTH(
    opcode=RC.ACKNOWLEDGE,
    psn=send_inv_req[BTH].psn,
    dqpn=dst_qpn,
)
send_inv_ack = (
    IP(dst=arg_res.dst_ip)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / send_inv_ack_bth
    / AETH(code="ACK", value=31, msn=1)
)
send_inv_ack.show()
send(send_inv_ack)
src_epsn += 2

# Exchange send done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", SendDone), peer_addr)
_ = struct.unpack("<i", exch_data)

###############################################################################
# Case 11: server write to client retry due to wrong PSN and exceed the retry limit
###############################################################################

case_no += 1
logging.info(f"Case {case_no} start...")

# Exchange write size
udp_sock.sendto(struct.pack("<iq", WriteRetrySeq, -1), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack("<iq", exch_data)
_, write_size = parsed_fields

# RoCE write imm, NAK sequence error retry and exceed retry limit
write_req_pkt_num = Util.compute_wr_pkt_num(write_size, PMTU)
for r in range(dst_retry_cnt):
    for i in range(write_req_pkt_num):
        roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
        write_req = BTH(roce_bytes)
        assert write_req[BTH].psn == src_epsn + i, "write request PSN not match ePSN"
        write_req.show()
    # NAK sequence error
    nak_seq_err_bth = BTH(
        opcode=RC.ACKNOWLEDGE,
        psn=src_epsn,
        dqpn=dst_qpn,
    )
    nak_seq_err_aeth = AETH(code="NAK", value=0, msn=1)
    nak_seq_err_resp = (
        IP(dst=arg_res.dst_ip)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / nak_seq_err_bth
        / nak_seq_err_aeth
    )
    nak_seq_err_resp.show()
    send(nak_seq_err_resp)
# Since the write requests are not ACK-ed, so src_epsn cannot be updated
# src_epsn += write_req_pkt_num


udp_sock.close()
roce_sock.close()
