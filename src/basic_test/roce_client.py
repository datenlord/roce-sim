import math
import socket
import struct

from multiprocessing import Process
from scapy.all import *

# from scapy.contrib.roce import BTH, AETH, opcode
from roce import AETH, AtomicAckETH, AtomicETH, BTH, ImmDt, RETH, opcode

PMTU = 256
MSG_SIZE = 720

DST_IP = "192.168.122.190"
SRC_IP = "192.168.122.238"
ROCE_PORT = 4791
DST_PORT = 9527
SRC_PORT = 6543
UDP_BUF_SIZE = 2048

S_VA = "0000556acaa2ea50"
S_RKEY = "00000208"
S_QPN = "00000011"
S_LID = "0000"
# S_GID = 'fe80000000000000505400fffea7d042'
S_GID = "00000000000000000000ffffc0a87aee"

ReceiveReady = 0
SendSize = 1
ReadSize = 2
WriteSize = 3
WriteImm = 4
WriteDone = 5
AtomicReady = 6
AtomicDone = 7

src_cpsn = 0
src_npsn = 0
src_epsn = 0

# RoCE socket
roce_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
roce_bind_addr = ("0.0.0.0", ROCE_PORT)
roce_sock.bind(roce_bind_addr)

# Connect to server
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_bind_addr = ("0.0.0.0", SRC_PORT)
udp_sock.bind(client_bind_addr)
srv_addr = (DST_IP, DST_PORT)
udp_sock.sendto(struct.pack("c", b"1"), srv_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack("<c", exch_data))

# Receive metadata
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack(">QIIH16s", exch_data)
dst_va, dst_rkey, dst_qpn, dst_lid, dst_gid = parsed_fields
print(parsed_fields)
# Send metadata
client_metadata = S_VA + S_RKEY + S_QPN + S_LID + S_GID
udp_sock.sendto(bytes.fromhex(client_metadata), peer_addr)

# Exchange receive ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", ReceiveReady), peer_addr)
print(struct.unpack("<i", exch_data))

# Exchange send size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", SendSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, send_size = parsed_fields
print(f"send_size={send_size}")
print(parsed_fields)

# RoCE send and ack
send_pkt_num = math.ceil(send_size / PMTU)
# roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=send_pkt_num)
# send_req = roce_pkts[0]
roce_pkts = []
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req.psn == src_epsn + i, "send request not match epsn"
    roce_pkts.append(send_req)
    send_req.show()
ack_bth = BTH(
    opcode=opcode("RC", "ACKNOWLEDGE")[0],
    psn=src_epsn + send_pkt_num - 1,
    dqpn=dst_qpn,
)
ack = (
    IP(dst=DST_IP)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / ack_bth
    / AETH(code="ACK", value=31, msn=1)
)
ack.show()
send(ack)
src_epsn += send_pkt_num

# Exchange read size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", ReadSize, -1), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
_, read_size = parsed_fields
print(parsed_fields)

# RoCE read and ack
read_resp_pkt_num = math.ceil(read_size / PMTU)
read_bth = BTH(
    opcode=opcode("RC", "RDMA_READ_REQUEST")[0],
    psn=src_cpsn,
    dqpn=dst_qpn,
)
read_reth = RETH(va=dst_va, rkey=dst_rkey, dlen=read_size)
read_req = IP(dst=DST_IP) / UDP(dport=ROCE_PORT, sport=ROCE_PORT) / read_bth / read_reth
read_req.show()
send(read_req)
src_npsn = src_cpsn + read_resp_pkt_num
ans = []
for i in range(read_resp_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    read_resp = BTH(roce_bytes)
    ans.append(read_resp)
    read_resp.show()
# ans, unans = sr(read_req, multi=True, timeout=1)
# assert len(ans) == 1, 'should receive 1 read response packet'
# read_resp = ans[0].answer
# read_resp.show()
assert read_resp.psn == src_npsn - 1, "read response PSN not match"
src_cpsn = src_npsn

# Exchange write size
write_str = "RDMA_Write_Operation"
write_size = MSG_SIZE  # len(write_str)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<iq", WriteSize, write_size), peer_addr)
parsed_fields = struct.unpack("<iq", exch_data)
print(parsed_fields)

# RoCE write and ack
write_reth = RETH(va=dst_va, rkey=dst_rkey, dlen=write_size)
if write_size <= PMTU:
    write_bth = BTH(
        opcode=opcode("RC", "RDMA_WRITE_ONLY")[0],
        psn=src_cpsn,
        dqpn=dst_qpn,
        ackreq=True,
    )
    write_data = struct.pack(f"<{write_size}s", bytearray(write_str, "ascii"))
    write_req = (
        IP(dst=DST_IP)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / write_bth
        / write_reth
        / Raw(load=write_data)
    )
    write_req.show()
    send(write_req)
    src_npsn = src_cpsn + 1
else:
    write_req_pkt_num = math.ceil(write_size / PMTU)
    write_bth = BTH(
        opcode=opcode("RC", "RDMA_WRITE_FIRST")[0],
        psn=src_cpsn,
        dqpn=dst_qpn,
        ackreq=False,
    )
    write_data = struct.pack(f"<{PMTU}s", bytearray(write_str, "ascii"))
    write_req = (
        IP(dst=DST_IP)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / write_bth
        / write_reth
        / Raw(load=write_data)
    )
    write_req.show()
    send(write_req)

    write_req_mid_pkt_num = write_req_pkt_num - 2
    for i in range(write_req_mid_pkt_num):
        write_bth = BTH(
            opcode=opcode("RC", "RDMA_WRITE_MIDDLE")[0],
            psn=src_cpsn + i + 1,
            dqpn=dst_qpn,
            ackreq=False,
        )
        write_data = struct.pack(f"<{PMTU}s", bytearray(write_str, "ascii"))
        write_req = (
            IP(dst=DST_IP)
            / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
            / write_bth
            / Raw(load=write_data)
        )
        write_req.show()
        send(write_req)

    last_write_size = write_size % PMTU
    write_bth = BTH(
        opcode=opcode("RC", "RDMA_WRITE_LAST")[0],
        psn=src_cpsn + write_req_mid_pkt_num + 1,
        dqpn=dst_qpn,
        ackreq=True,
    )
    write_data = struct.pack(f"<{last_write_size}s", bytearray(write_str, "ascii"))
    write_req = (
        IP(dst=DST_IP)
        / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
        / write_bth
        / Raw(load=write_data)
    )
    write_req.show()
    send(write_req)
    src_npsn = src_cpsn + write_req_pkt_num
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_resp = BTH(roce_bytes)
# write_resp = sr1(write_req, timeout=1)
# ans, unans = sr(write_req, multi=False, timeout=1) # retry=-2
# assert len(ans) == 1, 'should receive 1 write response packet'
# write_resp = ans[0].answer
write_resp.show()
assert write_resp.psn == src_npsn - 1, "write response PSN not match"
src_cpsn = src_npsn

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", WriteImm), peer_addr)
parsed_fields = struct.unpack("<i", exch_data)
print(parsed_fields)

# RoCE write with imm and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_imm_req = BTH(roce_bytes)
assert write_imm_req.psn == src_epsn, "write imm requst not match epsn"
write_imm_req.show()
write_imm_resp_bth = BTH(
    opcode=opcode("RC", "ACKNOWLEDGE")[0],
    psn=src_epsn,
    dqpn=dst_qpn,
)
write_imm_resp = (
    IP(dst=DST_IP)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / write_imm_resp_bth
    / AETH(code="ACK", value=31, msn=1)
)
send(write_imm_resp)
src_epsn += 1

# Exchange write done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", WriteDone), peer_addr)
parsed_fields = struct.unpack("<i", exch_data)
print(parsed_fields)

# Exchange atomic ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", AtomicReady), peer_addr)
print(struct.unpack("<i", exch_data))
# RoCE atomic and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
# roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=1)
# atomic_req = roce_pkts[0]
atomic_req.show()
atomic_ack_bth = BTH(
    opcode=opcode("RC", "ATOMIC_ACKNOWLEDGE")[0],
    psn=atomic_req[BTH].psn,
    dqpn=dst_qpn,
)
atomic_ack = (
    IP(dst=DST_IP)
    / UDP(dport=ROCE_PORT, sport=ROCE_PORT)
    / atomic_ack_bth
    / AETH(code="ACK", value=31, msn=1)
    / AtomicAckETH(orig=0)
)
atomic_ack.show()
send(atomic_ack)
# Exchange atomic done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack("<i", AtomicDone), peer_addr)
print(struct.unpack("<i", exch_data))

udp_sock.close()
roce_sock.close()
