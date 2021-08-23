import argparse
import math
import socket
import struct

from multiprocessing import Process
from scapy.all import *
from roce import AETH, AtomicAckETH, AtomicETH, BTH, ImmDt, RETH
from roce_enum import RC

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

###############################################################################
# Case 1: client send zero data with imm to server and retry due to NAK sequence error
###############################################################################

# Exchange send imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', SendImm), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(struct.unpack('<i', exch_data))

# RoCE send imm and ack
src_npsn = src_cpsn + 1
wrong_psn = src_npsn + 2
send_bth = BTH(
    opcode = RC.SEND_ONLY_WITH_IMMEDIATE,
    psn = wrong_psn,
    dqpn = dst_qpn,
    ackreq = True,
)
send_imm_data = ImmDt(data=1234)
send_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/send_bth/send_imm_data
send_req.show()
send(send_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
seq_nak_resp = BTH(roce_bytes)
assert seq_nak_resp[BTH].psn == src_cpsn, 'responder ePSN not match requester cPSN'
assert (
    seq_nak_resp[BTH].opcode == RC.ACKNOWLEDGE
    and seq_nak_resp[AETH].code == 3 and seq_nak_resp[AETH].value == 0
), 'send with wrong PSN should receive NAK sequence error'
send_req[BTH].psn = src_cpsn
send(send_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
send_resp = BTH(roce_bytes)
send_resp.show()
assert send_resp.psn == src_npsn - 1, 'send with imm response PSN not match expected'
src_cpsn = src_npsn

###############################################################################
# Case 2: client write zero data with imm to server and retried due to RNR
###############################################################################

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteImm), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# RoCE write with imm and ack
src_npsn = src_cpsn + 1
write_imm_bth = BTH(
    opcode = RC.RDMA_WRITE_ONLY_WITH_IMMEDIATE,
    psn = src_cpsn,
    dqpn = dst_qpn,
    ackreq = True,
)
write_imm_reth = RETH(va=dst_va, rkey=dst_rkey, dlen=0)
write_imm_data = ImmDt(data=1234)
write_imm_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_imm_bth/write_imm_reth/write_imm_data
write_imm_req.show()
send(write_imm_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
rnr_nak_resp = BTH(roce_bytes)
assert rnr_nak_resp[BTH].opcode == RC.ACKNOWLEDGE and rnr_nak_resp[AETH].code == 1, 'write with imm should have NAK RNR when no receive buffer'
send(write_imm_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
write_imm_resp = BTH(roce_bytes)
write_imm_resp.show()
assert write_imm_resp.psn == src_npsn - 1, 'write with imm response PSN not match expected'
src_cpsn = src_npsn

###############################################################################
# Case 3: client read zero data from server
###############################################################################

# Exchange read zero
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', ReadZero), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# RoCE read zero and ack
src_npsn = src_cpsn + 1
read_zero_bth = BTH(
    opcode = RC.RDMA_READ_REQUEST,
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
assert read_zero_resp.psn == src_npsn - 1, 'read zero response PSN not match expected'
src_cpsn = src_npsn

###############################################################################
# Case 4: server send to client without requesting ACK and retry due to NAK sequence error
###############################################################################

# Exchange send size and RNR NAK
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', SendSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, send_size = parsed_fields
print(f'send_size={send_size}')
print(parsed_fields)

# RoCE send and NAK seq err retry without ACK
send_pkt_num = math.ceil(send_size / PMTU) if send_size > 0 else 1
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req.psn == src_epsn + i, 'send request PSN not match ePSN'
    send_req.show()
seq_nak_bth = BTH(
    opcode = RC.ACKNOWLEDGE,
    psn = src_epsn,
    dqpn = dst_qpn,
)
seq_nak_aeth = AETH(code='NAK', value=0, msn=1)
seq_nak_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/seq_nak_bth/seq_nak_aeth
seq_nak_resp.show()
send(seq_nak_resp)
# RoCE NAK seq err retry send request
roce_pkts = []
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req.psn == src_epsn + i, 'send request PSN not match ePSN'
    roce_pkts.append(send_req)
    send_req.show()
src_epsn += send_pkt_num

###############################################################################
# Case 5: client send atomic request to server
###############################################################################

# Exchange atomic ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicReady), peer_addr)
print(struct.unpack('<i', exch_data))

# RoCE atomic and ack
src_npsn = src_cpsn + 1
atomic_bth = BTH(
    opcode = RC.FETCH_ADD,
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
atomic_req = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/atomic_bth/atomic_eth
atomic_req.show()
send(atomic_req)
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_resp = BTH(roce_bytes)
atomic_resp.show()
assert atomic_resp.psn == src_npsn - 1, 'atomic response PSN not match expected'
src_cpsn = src_npsn

###############################################################################
# Case 6: client send atomic request to server
###############################################################################

# Exchange atomic ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicReady), peer_addr)
print(struct.unpack('<i', exch_data))

# RoCE atomic and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
atomic_req = BTH(roce_bytes)
atomic_req.show()
assert atomic_req[BTH].psn == src_epsn, 'atomic request PSN not match ePSN'
atomic_ack_bth = BTH(
    opcode = RC.ATOMIC_ACKNOWLEDGE,
    psn = atomic_req[BTH].psn,
    dqpn = dst_qpn,
)
atomic_ack = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/atomic_ack_bth/AETH(code='ACK', value=31, msn=1)/AtomicAckETH(orig=0)
atomic_ack.show()
send(atomic_ack)
src_epsn += 1

###############################################################################
# Case 7: server write with imm to client and RNR retry the last write request
###############################################################################

# Exchange write imm size
write_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', WriteSize, write_size), peer_addr)
print(struct.unpack('<iq', exch_data))

# RoCE write imm, rnr retry and ack
write_req_pkt_num = math.ceil(write_size / PMTU) if write_size > 0 else 1
print(f'write request packet num={write_req_pkt_num}')
for i in range(write_req_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    write_req = BTH(roce_bytes)
    assert write_req.psn == src_epsn + i, 'write request PSN not match ePSN'
    write_req.show()
# RNR nak
rnr_nak_bth = BTH(
    opcode = RC.ACKNOWLEDGE,
    psn = src_epsn + write_req_pkt_num - 1,
    dqpn = dst_qpn,
)
rnr_nak_aeth = AETH(code='RNR', value=0, msn=1)
rnr_nak_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/rnr_nak_bth/rnr_nak_aeth
rnr_nak_resp.show()
send(rnr_nak_resp)
# Retried last write request
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
retry_write_last_req = BTH(roce_bytes)
retry_write_last_req.show()
assert write_req.psn == src_epsn + write_req_pkt_num - 1, 'retried write request PSN not match ePSN'
write_resp_bth = BTH(
    opcode = RC.ACKNOWLEDGE,
    psn = src_epsn + write_req_pkt_num - 1,
    dqpn = dst_qpn,
)
write_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_resp_bth/AETH(code='ACK', value=31, msn=1)
write_resp.show()
send(write_resp)
src_epsn += write_req_pkt_num

###############################################################################
# Case 8: server send to client without requesting ACK
###############################################################################

# Exchange send size and rnr nak
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', SendSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, send_size = parsed_fields
print(f'send_size={send_size}')
print(parsed_fields)

# RoCE send and rnr retry without ack
send_pkt_num = math.ceil(send_size / PMTU) if send_size > 0 else 1
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
send_req = BTH(roce_bytes)
assert send_req.psn == src_epsn, 'send request PSN not match ePSN'
rnr_nak_bth = BTH(
    opcode = RC.ACKNOWLEDGE,
    psn = send_req[BTH].psn,
    dqpn = dst_qpn,
)
rnr_nak_aeth = AETH(code='RNR', value=0, msn=1)
rnr_nak_resp = IP(dst=arg_res.dst_ip)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/rnr_nak_bth/rnr_nak_aeth
rnr_nak_resp.show()
send(rnr_nak_resp)
for i in range(send_pkt_num - 1):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req.psn == src_epsn + i + 1, 'send request PSN not match ePSN'
    send_req.show()
# RoCE rnr retry send request
roce_pkts = []
for i in range(send_pkt_num):
    roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
    send_req = BTH(roce_bytes)
    assert send_req.psn == src_epsn + i, 'send request PSN not match ePSN'
    roce_pkts.append(send_req)
    send_req.show()
src_epsn += send_pkt_num

###############################################################################
# Case 9: server read from client with retried request due to NAK sequence error
###############################################################################

# Exchange read size
read_str = 'RDMA_Read_Operation'
read_size = MSG_SIZE # len(read_str) #
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', ReadSize, read_size), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, read_size = parsed_fields
print(parsed_fields)

# RoCE read, nak seq retry and ack
roce_bytes, peer_addr = roce_sock.recvfrom(UDP_BUF_SIZE)
read_req = BTH(roce_bytes)
read_req.show()
assert read_req[BTH].psn == src_epsn, 'read request PSN not match ePSN'
read_size = read_req[RETH].dlen
read_resp_pkt_num = math.ceil(read_size / PMTU)
read_aeth = AETH(code='ACK', value=31, msn=1)
nak_seq_aeth = AETH(code='NAK', value=0, msn=1)
if read_size <= PMTU:
    # Ask for retry
    nak_seq_bth = BTH(
        opcode = RC.ACKNOWLEDGE,
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
        opcode = RC.RDMA_READ_RESPONSE_ONLY,
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
        opcode = RC.ACKNOWLEDGE,
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
        opcode = RC.RDMA_READ_RESPONSE_FIRST,
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
            opcode = RC.ACKNOWLEDGE,
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
            opcode = RC.RDMA_READ_RESPONSE_FIRST,
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
        opcode = RC.ACKNOWLEDGE,
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
        opcode = RC.RDMA_READ_RESPONSE_ONLY,
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
    opcode = RC.RDMA_READ_REQUEST,
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
        opcode = RC.RDMA_WRITE_ONLY,
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
        opcode = RC.RDMA_WRITE_FIRST,
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
            opcode = RC.RDMA_WRITE_MIDDLE,
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
        opcode = RC.RDMA_WRITE_LAST,
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
    opcode = RC.ACKNOWLEDGE,
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
    opcode = RC.ATOMIC_ACKNOWLEDGE,
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
