import argparse
import math
import socket
import struct

from multiprocessing import Process
from scapy.all import *
from roce import AETH, AtomicAckETH, AtomicETH, BTH, ImmDt, RETH, opcode

POS_IN_MR = 8
MR_SIZE = 1024
PMTU = 256
MSG_SIZE = MR_SIZE - POS_IN_MR

#DST_IP = '192.168.122.238'
ROCE_PORT = 4791
DST_PORT = 9527
SRC_PORT = 6543
UDP_BUF_SIZE = 2048

S_VA = '0000556acaa2ea50'
S_RKEY = 208
S_QPN = 17
S_LID = '0000'
#S_GID = '00000000000000000000ffffc0a87abe'

ReceiveReady = 0
SendImm = 1
WriteImm = 2
ReadZero = 3
SendSize = 4
ReadSize = 5
WriteSize = 6
WriteDone = 7
AtomicReady = 8
AtomicDone = 9

src_cpsn = 0
src_npsn = 0
src_epsn = 0

parser = argparse.ArgumentParser(description='Input server IP and client IP')
parser.add_argument('-s', action='store', dest='src_ip')
parser.add_argument('-d', action='store', dest='dst_ip')
arg_res = parser.parse_args()

# RoCE socket
roce_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
roce_bind_addr = ('0.0.0.0', ROCE_PORT)
roce_sock.bind(roce_bind_addr)

# Connect to server
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_bind_addr = ('0.0.0.0', SRC_PORT)
udp_sock.bind(client_bind_addr)
srv_addr = (arg_res.dst_ip, DST_PORT)
udp_sock.sendto(struct.pack('c', b'1'), srv_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<c', exch_data))

# Receive metadata
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack('>QIIH16s', exch_data)
dst_va, dst_rkey, dst_qpn, dst_lid, dst_gid = parsed_fields
print(parsed_fields)
# Send metadata
src_va = '{:016x}'.format(POS_IN_MR)
src_rkey = '{:08x}'.format(S_RKEY)
src_qpn = '{:08x}'.format(S_QPN)
src_gid = '{0:0>32}'.format('ffff' + socket.inet_aton(arg_res.src_ip).hex())
client_metadata = src_va + src_rkey + src_qpn + S_LID + src_gid
udp_sock.sendto(bytes.fromhex(client_metadata), peer_addr)

# Exchange receive ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', ReceiveReady), peer_addr)
print(struct.unpack('<i', exch_data))

# Exchange send imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', SendImm), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(struct.unpack('<i', exch_data))

# RoCE send imm and ack
src_npsn = src_cpsn + 1
send_bth = BTH(
    opcode = opcode('RC', 'SEND_ONLY_WITH_IMMEDIATE')[0],
    psn = src_cpsn,
    dqpn = dst_qpn,
    ackreq = True,
)
send_imm_data = ImmDt(data=1234)
send_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/send_bth/send_imm_data
send_req.show()
send(send_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
send_resp = BTH(roce_bytes)
#ans, unans = sr(send_req, multi=False, timeout=1)
#assert len(ans) == 1, 'should receive 1 send response packet'
#send_resp = ans[0].answer
send_resp.show()
assert send_resp.psn == src_npsn - 1, 'send imm response PSN not match'
src_cpsn = src_npsn

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
write_imm_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_imm_bth/write_imm_reth/write_imm_data
write_imm_req.show()
send(write_imm_req)
src_npsn = src_cpsn + 1
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_imm_resp = BTH(roce_bytes)
write_imm_resp.show()
assert write_imm_resp.psn == src_npsn - 1, 'write imm response PSN not match'
src_cpsn = src_npsn

# Exchange read zero
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', ReadZero), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# RoCE read zero and ack
src_npsn = src_cpsn + 1
read_zero_bth = BTH(
    opcode = opcode('RC', 'RDMA_READ_REQUEST')[0],
    psn = src_cpsn,
    dqpn = dst_qpn,
)
read_zero_reth = RETH(va=0, rkey=0, dlen=0)
read_zero_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_zero_bth/read_zero_reth
read_zero_req.show()
send(read_zero_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
read_zero_resp = BTH(roce_bytes)
read_zero_resp.show()
assert read_zero_resp.psn == src_npsn - 1, 'read zero response PSN not match'
src_cpsn = src_npsn

# Exchange send size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', SendSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, send_size = parsed_fields
print(f'send_size={send_size}')
print(parsed_fields)

# RoCE send and ack
send_pkt_num = math.ceil(send_size / PMTU) if send_size > 0 else 1
roce_pkts = []
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req.psn == src_epsn + i, 'send request not match epsn'
    roce_pkts.append(send_req)
    send_req.show()
src_epsn += send_pkt_num

# Exchange read size
read_str = 'RDMA_Read_Operation'
read_size = MSG_SIZE # len(read_str) #
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
nak_seq_aeth = AETH(code='NAK', value=0, msn=1)
if read_size <= PMTU:
    # Ask for retry
    nak_seq_bth = BTH(
        opcode = opcode('RC', 'ACKNOWLEDGE')[0],
        psn = read_req[BTH].psn,
        dqpn = dst_qpn,
    )
    nak_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/nak_seq_bth/nak_seq_aeth
    nak_resp.show()
    send(nak_resp)
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    retry_read_req = BTH(roce_bytes)
    assert retry_read_req[BTH].psn == read_req[BTH].psn

    read_resp_bth = BTH(
        opcode = opcode('RC', 'RDMA_READ_RESPONSE_ONLY')[0],
        psn = read_req[BTH].psn,
        dqpn = dst_qpn,
    )
    read_data = struct.pack(f'<{read_size}s', bytearray(read_str, 'ascii'))
    read_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/read_aeth/Raw(load=read_data)
    read_resp.show()
    send(read_resp)
else:
    # Retry whole read
    nak_seq_bth = BTH(
        opcode = opcode('RC', 'ACKNOWLEDGE')[0],
        psn = src_epsn,
        dqpn = dst_qpn,
    )
    nak_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/nak_seq_bth/nak_seq_aeth
    nak_resp.show()
    send(nak_resp)
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    retry_read_req = BTH(roce_bytes)
    assert retry_read_req[BTH].psn == src_epsn

    read_resp_bth = BTH(
        opcode = opcode('RC', 'RDMA_READ_RESPONSE_FIRST')[0],
        psn = src_epsn,
        dqpn = dst_qpn,
    )
    read_data = struct.pack(f'<{PMTU}s', bytearray(read_str, 'ascii'))
    read_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/read_aeth/Raw(load=read_data)
    read_resp.show()
    send(read_resp)

    read_resp_mid_pkt_num = read_resp_pkt_num - 2
    for i in range(read_resp_mid_pkt_num):
        # Retry read from every middle response
        nak_seq_bth = BTH(
            opcode = opcode('RC', 'ACKNOWLEDGE')[0],
            psn = src_epsn + i + 1,
            dqpn = dst_qpn,
        )
        nak_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/nak_seq_bth/nak_seq_aeth
        nak_resp.show()
        send(nak_resp)
        roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
        retry_read_req = BTH(roce_bytes)
        assert retry_read_req[BTH].psn == src_epsn + i + 1

        read_resp_bth = BTH(
            opcode = opcode('RC', 'RDMA_READ_RESPONSE_FIRST')[0],
            psn = src_epsn + i + 1,
            dqpn = dst_qpn,
        )
        read_data = struct.pack(f'<{PMTU}s', bytearray(read_str, 'ascii'))
        mid_read_data_len = len(read_data)
        print(f'mid read data len={mid_read_data_len}')
        read_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/read_aeth/Raw(load=read_data)
        read_resp.show()
        send(read_resp)

    last_read_size = read_size % PMTU
    # Retry read from the last response
    nak_seq_bth = BTH(
        opcode = opcode('RC', 'ACKNOWLEDGE')[0],
        psn = src_epsn + read_resp_mid_pkt_num + 1,
        dqpn = dst_qpn,
    )
    nak_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/nak_seq_bth/nak_seq_aeth
    nak_resp.show()
    send(nak_resp)
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    retry_read_req = BTH(roce_bytes)
    assert retry_read_req[BTH].psn == src_epsn + read_resp_mid_pkt_num + 1

    read_resp_bth = BTH(
        opcode = opcode('RC', 'RDMA_READ_RESPONSE_ONLY')[0],
        psn = src_epsn + read_resp_mid_pkt_num + 1,
        dqpn = dst_qpn,
    )
    read_data = struct.pack(f'<{last_read_size}s', bytearray(read_str, 'ascii'))
    read_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/read_aeth/Raw(load=read_data)
    read_resp.show()
    send(read_resp)
src_epsn += read_resp_pkt_num

# Exchange write done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteDone), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

exit()

# Exchange read size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', ReadSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, read_size = parsed_fields
print(parsed_fields)

# RoCE read and ack
read_resp_pkt_num = math.ceil(read_size / PMTU)
read_bth = BTH(
    opcode = opcode('RC', 'RDMA_READ_REQUEST')[0],
    psn = src_cpsn,
    dqpn = dst_qpn,
)
read_reth = RETH(va=dst_va, rkey=dst_rkey, dlen=read_size)
read_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_bth/read_reth
read_req.show()
send(read_req)
src_npsn = src_cpsn + read_resp_pkt_num
ans = []
for i in range(read_resp_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    read_resp = BTH(roce_bytes)
    ans.append(read_resp)
    read_resp.show()
#ans, unans = sr(read_req, multi=True, timeout=1)
#assert len(ans) == 1, 'should receive 1 read response packet'
#read_resp = ans[0].answer
#read_resp.show()
assert read_resp.psn == src_npsn - 1, 'read response PSN not match'
src_cpsn = src_npsn

# Exchange write size
write_str = 'RDMA_Write_Operation'
write_size = MSG_SIZE # len(write_str)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', WriteSize, write_size), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
print(parsed_fields)

# RoCE write and ack
write_reth = RETH(va=dst_va, rkey=dst_rkey, dlen=write_size)
if write_size <= PMTU:
    write_bth = BTH(
        opcode = opcode('RC', 'RDMA_WRITE_ONLY')[0],
        psn = src_cpsn,
        dqpn = dst_qpn,
        ackreq = True,
    )
    write_data = struct.pack(f'<{write_size}s', bytearray(write_str, 'ascii'))
    write_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_bth/write_reth/Raw(load=write_data)
    write_req.show()
    send(write_req)
    src_npsn = src_cpsn + 1
else:
    write_req_pkt_num = math.ceil(write_size / PMTU)
    write_bth = BTH(
        opcode = opcode('RC', 'RDMA_WRITE_FIRST')[0],
        psn = src_cpsn,
        dqpn = dst_qpn,
        ackreq = False,
    )
    write_data = struct.pack(f'<{PMTU}s', bytearray(write_str, 'ascii'))
    write_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_bth/write_reth/Raw(load=write_data)
    write_req.show()
    send(write_req)

    write_req_mid_pkt_num = write_req_pkt_num - 2
    for i in range(write_req_mid_pkt_num):
        write_bth = BTH(
            opcode = opcode('RC', 'RDMA_WRITE_MIDDLE')[0],
            psn = src_cpsn + i + 1,
            dqpn = dst_qpn,
            ackreq = False,
        )
        write_data = struct.pack(f'<{PMTU}s', bytearray(write_str, 'ascii'))
        write_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_bth/Raw(load=write_data)
        write_req.show()
        send(write_req)

    last_write_size = write_size % PMTU
    write_bth = BTH(
        opcode = opcode('RC', 'RDMA_WRITE_LAST')[0],
        psn = src_cpsn + write_req_mid_pkt_num + 1,
        dqpn = dst_qpn,
        ackreq = True,
    )
    write_data = struct.pack(f'<{last_write_size}s', bytearray(write_str, 'ascii'))
    write_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_bth/Raw(load=write_data)
    write_req.show()
    send(write_req)
    src_npsn = src_cpsn + write_req_pkt_num
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_resp = BTH(roce_bytes)
#write_resp = sr1(write_req, timeout=1)
#ans, unans = sr(write_req, multi=False, timeout=1) # retry=-2
#assert len(ans) == 1, 'should receive 1 write response packet'
#write_resp = ans[0].answer
write_resp.show()
assert write_resp.psn == src_npsn - 1, 'write response PSN not match'
src_cpsn = src_npsn

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteImm), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# RoCE write with imm and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_imm_req = BTH(roce_bytes)
assert write_imm_req.psn == src_epsn, 'write imm requst not match epsn'
write_imm_req.show()
write_imm_resp_bth = BTH(
    opcode = opcode('RC', 'ACKNOWLEDGE')[0],
    psn = src_epsn,
    dqpn = dst_qpn,
)
write_imm_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_imm_resp_bth/AETH(code='ACK', value=31, msn=1)
send(write_imm_resp)
src_epsn += 1

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
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
#roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=1)
#atomic_req = roce_pkts[0]
atomic_req.show()
atomic_ack_bth = BTH(
    opcode = opcode('RC', 'ATOMIC_ACKNOWLEDGE')[0],
    psn = atomic_req[BTH].psn,
    dqpn = dst_qpn,
)
atomic_ack = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/atomic_ack_bth/AETH(code='ACK', value=31, msn=1)/AtomicAckETH(orig=0)
atomic_ack.show()
send(atomic_ack)
# Exchange atomic done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicDone), peer_addr)
print(struct.unpack('<i', exch_data))

udp_sock.close()
roce_sock.close()
