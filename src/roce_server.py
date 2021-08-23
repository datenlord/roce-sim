import socket
import struct

from multiprocessing import Process
from scapy.all import *
#from scapy.contrib.roce import BTH, AETH, opcode
from roce import AETH, AtomicAckETH, AtomicETH, BTH, ImmDt, RETH, opcode

PMTU = 256
MSG_SIZE = 720

DST_IP = '192.168.122.190'
SRC_IP = '192.168.122.238'
ROCE_PORT = 4791
#DST_PORT = 9527
SRC_PORT = 9527
UDP_BUF_SIZE = 1024

S_VA = '0000556acaa2ea50'
S_RKEY = '00000208'
S_QPN = '00000011'
S_LID = '0000'
#S_GID = 'fe80000000000000505400fffea7d042'
S_GID = '00000000000000000000ffffc0a87aee'

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
roce_bind_addr = ('0.0.0.0', ROCE_PORT)
roce_sock.bind(roce_bind_addr)

# Wait for connection
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_bind_addr = ('0.0.0.0', SRC_PORT)
udp_sock.bind(server_bind_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<c', exch_data))
udp_sock.sendto(struct.pack('c', b'2'), peer_addr)

# Send metadata
server_metadata = S_VA + S_RKEY + S_QPN + S_LID + S_GID
udp_sock.sendto(bytes.fromhex(server_metadata), peer_addr)
# Recive metadata
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack('>QIIH16s', exch_data)
dst_va, dst_rkey, dst_qpn, dst_lid, dst_gid = parsed_fields
print(parsed_fields)

# Exchange receive ready
udp_sock.sendto(struct.pack('<i', ReceiveReady), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<i', exch_data))

# Exchange send size
send_str = 'RDMA_Send_Operation'
send_size = MSG_SIZE # len(send_str)
udp_sock.sendto(struct.pack('<iq', SendSize, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<iq', exch_data))

# RoCE send and ack
send_req_pkt_num = math.ceil(send_size / PMTU)
src_npsn = src_cpsn + send_req_pkt_num
if send_size <= PMTU: 
    send_bth = BTH(
        opcode = opcode('RC', 'SEND_ONLY')[0],
        psn = src_cpsn,
        dqpn = dst_qpn,
        ackreq = True,
    )
    send_data = struct.pack(f'<{send_size}s', bytearray(send_str, 'ascii'))
    send_req = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/send_bth/Raw(load=send_data)
    send_req.show()
    send(send_req)
else:
    send_bth = BTH(
        opcode = opcode('RC', 'SEND_FIRST')[0],
        psn = src_cpsn,
        dqpn = dst_qpn,
        ackreq = False,
    )
    send_data = struct.pack(f'<{PMTU}s', bytearray(send_str, 'ascii'))
    send_req = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/send_bth/Raw(load=send_data)
    send_req.show()
    send(send_req)

    send_req_mid_pkt_num = send_req_pkt_num - 2
    for i in range(send_req_mid_pkt_num):
        send_bth = BTH(
            opcode = opcode('RC', 'SEND_MIDDLE')[0],
            psn = src_cpsn + i + 1,
            dqpn = dst_qpn,
            ackreq = False,
        )
        send_data = struct.pack(f'<{PMTU}s', bytearray(send_str, 'ascii'))
        send_req = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/send_bth/Raw(load=send_data)
        send_req.show()
        send(send_req)

    last_send_size = send_size % PMTU
    send_bth = BTH(
        opcode = opcode('RC', 'SEND_LAST')[0],
        psn = src_cpsn + send_req_mid_pkt_num + 1,
        dqpn = dst_qpn,
        ackreq = True,
    )
    send_data = struct.pack(f'<{last_send_size}s', bytearray(send_str, 'ascii'))
    send_req = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/send_bth/Raw(load=send_data)
    send_req.show()
    send(send_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
send_resp = BTH(roce_bytes)
#ans, unans = sr(send_req, multi=False, timeout=1)
#assert len(ans) == 1, 'should receive 1 send response packet'
#send_resp = ans[0].answer
send_resp.show()
assert send_resp.psn == src_npsn - 1, 'send response PSN not match'
src_cpsn = src_npsn

# Exchange read size
read_str = 'RDMA_Read_Operation'
read_size = MSG_SIZE # len(read_str)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', ReadSize, read_size), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, read_size = parsed_fields
print(parsed_fields)

# RoCE read and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
read_req = BTH(roce_bytes)
#roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=1)
#read_req = roce_pkts[0]
read_req.show()
assert read_req[BTH].psn == src_epsn, 'expected PSN not match'
read_size = read_req[RETH].dlen
read_resp_pkt_num = math.ceil(read_size / PMTU)
read_aeth = AETH(code='ACK', value=31, msn=1)
if read_size <= PMTU:
    read_resp_bth = BTH(
        opcode = opcode('RC', 'RDMA_READ_RESPONSE_ONLY')[0],
        psn = read_req[BTH].psn,
        dqpn = dst_qpn,
    )
    read_data = struct.pack(f'<{read_size}s', bytearray(read_str, 'ascii'))
    read_resp = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/read_aeth/Raw(load=read_data)
    read_resp.show()
    send(read_resp)
else:
    read_resp_bth = BTH(
        opcode = opcode('RC', 'RDMA_READ_RESPONSE_FIRST')[0],
        psn = src_epsn,
        dqpn = dst_qpn,
    )
    read_data = struct.pack(f'<{PMTU}s', bytearray(read_str, 'ascii'))
    read_resp = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/read_aeth/Raw(load=read_data)
    read_resp.show()
    send(read_resp)

    read_resp_mid_pkt_num = read_resp_pkt_num - 2
    for i in range(read_resp_mid_pkt_num):
        read_resp_bth = BTH(
            opcode = opcode('RC', 'RDMA_READ_RESPONSE_MIDDLE')[0],
            psn = src_epsn + i + 1,
            dqpn = dst_qpn,
        )
        read_data = struct.pack(f'<{PMTU}s', bytearray(read_str, 'ascii'))
        mid_read_data_len = len(read_data)
        print(f'mid read data len={mid_read_data_len}')
        read_resp = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/Raw(load=read_data)
        read_resp.show()
        send(read_resp)

    last_read_size = read_size % PMTU
    read_resp_bth = BTH(
        opcode = opcode('RC', 'RDMA_READ_RESPONSE_LAST')[0],
        psn = src_epsn + read_resp_mid_pkt_num + 1,
        dqpn = dst_qpn,
    )
    read_data = struct.pack(f'<{last_read_size}s', bytearray(read_str, 'ascii'))
    read_resp = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/read_aeth/Raw(load=read_data)
    read_resp.show()
    send(read_resp)
src_epsn += read_resp_pkt_num

# Exchange write size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', WriteSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, write_size = parsed_fields
print(parsed_fields)

# RoCE write and ack
write_req_pkt_num = math.ceil(write_size / PMTU)
print(f'write request packet num={write_req_pkt_num}')
for i in range(write_req_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    write_req = BTH(roce_bytes)
    assert write_req.psn == src_epsn + i, 'write request PSN not match ePSN'
    write_req.show()
#roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=1)
#write_req = roce_pkts[0]
#write_req.show()
write_resp_bth = BTH(
    opcode = opcode('RC', 'ACKNOWLEDGE')[0],
    psn = src_epsn + write_req_pkt_num - 1,
    dqpn = dst_qpn,
)
write_resp = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_resp_bth/AETH(code='ACK', value=31, msn=1)
send(write_resp)
src_epsn += write_req_pkt_num

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteImm), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# RoCE write with imm and ack
write_imm_bth = BTH(
    opcode = opcode('RC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE')[0],
    psn = src_cpsn,
    dqpn = dst_qpn,
    ackreq = True,
)
write_imm_reth = RETH(va=dst_va, rkey=dst_rkey, dlen=0)
write_imm_data = ImmDt(data=1234)
write_imm_req = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_imm_bth/write_imm_reth/write_imm_data
write_imm_req.show()
send(write_imm_req)
src_npsn = src_cpsn + 1
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_imm_resp = BTH(roce_bytes)
write_imm_resp.show()
assert write_imm_resp.psn == src_npsn - 1, 'write imm response PSN not match'
src_cpsn = src_npsn

# Exchange write done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteDone), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# Exchange atomic ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicReady), peer_addr)
print(struct.unpack('<i', exch_data))
# RoCE atomic and ack
src_npsn = src_cpsn + 1
#roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=1)
#atomic_req = roce_pkts[0]
atomic_bth = BTH(
    opcode = opcode('RC', 'FETCH_ADD')[0],
    psn = src_cpsn,
    dqpn = dst_qpn,
    ackreq = True,
)
aligned_dst_va = ((dst_va + 7) >> 3) << 3
print(f'aligned dst va={aligned_dst_va}, dst va={dst_va}')
atomic_eth = AtomicETH(
    va = aligned_dst_va,
    rkey = dst_rkey,
    comp = 1,
    swap = 0,
)
atomic_req = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/atomic_bth/atomic_eth
atomic_req.show()
send(atomic_req)
#roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
#atomic_resp = BTH(roce_bytes)
#atomic_resp.show()
#assert atomic_resp.psn == src_npsn - 1, 'atomic response PSN not match'
src_cpsn = src_npsn
# Exchange atomic done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicDone), peer_addr)
print(struct.unpack('<i', exch_data))

udp_sock.close()
roce_sock.close()

