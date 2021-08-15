import socket
import struct
import logging
from roce_enum import *
from roce_v2 import *

MR_SIZE = 1024
MSG_SIZE = 720
SRC_PORT = 9527

S_VA = '000056482bb76120'
# S_RKEY = '00000208'
#S_QPN = '00000011'
S_LID = '0000'
S_GID = '00000000000000000000ffffc0a87aee'

POS_IN_MR = 8

ReceiveReady = 0
SendSize = 1
ReadSize = 2
WriteSize = 3
WriteImm = 4
WriteDone = 5
AtomicReady = 6
AtomicDone = 7

logging.basicConfig(level=logging.DEBUG)

# Build RoCE data structure
roce = RoCEv2()
pd = roce.alloc_pd()
cq = roce.create_cq()
qp = roce.create_qp(
    pd = pd,
    cq = cq,
    access_flags = ACCESS_FLAGS.LOCAL_WRITE
        | ACCESS_FLAGS.REMOTE_WRITE
        | ACCESS_FLAGS.REMOTE_READ
        | ACCESS_FLAGS.REMOTE_ATOMIC
)
mr = pd.reg_mr(
    va = int(S_VA, 16), length = MR_SIZE,
    access_flags = ACCESS_FLAGS.LOCAL_WRITE
        | ACCESS_FLAGS.REMOTE_WRITE
        | ACCESS_FLAGS.REMOTE_READ
        | ACCESS_FLAGS.REMOTE_ATOMIC
        | ACCESS_FLAGS.ZERO_BASED
)
mr.write(byte_data = b'000000001234567890ABCEDFGHIJKLMNOPQRSTUVWXYZ')

# Wait for connection
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_bind_addr = ('0.0.0.0', SRC_PORT)
udp_sock.bind(server_bind_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<c', exch_data))
udp_sock.sendto(struct.pack('c', b'2'), peer_addr)

# Send metadata
src_va = '{:016x}'.format(POS_IN_MR)
src_rkey = '{:08x}'.format(mr.rkey())
src_qpn = '{:08x}'.format(qp.qpn())
server_metadata = src_va + src_rkey + src_qpn + S_LID + S_GID
udp_sock.sendto(bytes.fromhex(server_metadata), peer_addr)
# Recive metadata
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack('>QIIH16s', exch_data)
dst_va, dst_rkey, dst_qpn, dst_lid, dst_gid = parsed_fields
print(parsed_fields)

# Setup QP, post receive
sg = SG(pos_in_mr = POS_IN_MR, length = mr.len() - POS_IN_MR, lkey = mr.lkey())
rr = RecvWR(sgl = mr)
qp.post_recv(rr)
qp.modify_qp(qps = QPS.RTR, dgid = dst_gid, dst_qpn = dst_qpn) # dqpn should be integer

# Exchange receive ready
udp_sock.sendto(struct.pack('<i', ReceiveReady), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<i', exch_data))

qp.modify_qp(qps = QPS.RTS)

# Exchange send size
send_size = MSG_SIZE
udp_sock.sendto(struct.pack('<iq', SendSize, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<iq', exch_data))

# RoCE send and ack
sg = SG(pos_in_mr = POS_IN_MR, length = send_size, lkey = mr.lkey())
sr = SendWR(
    opcode = WR_OPCODE.SEND_WITH_IMM,
    sgl = sg,
    send_flags = SEND_FLAGS.SIGNALED,
    imm_data_or_inv_rkey = 0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, 'cqe should exist'
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS

# Exchange read size
read_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', ReadSize, read_size), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, read_size = parsed_fields
print(parsed_fields)

# RoCE read and ack
mr.write(byte_data = b'00000000abcdefghijklmnopqrstuvwxyz')
roce.recv_pkts(1)

# Exchange write size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', WriteSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, write_size = parsed_fields
print(parsed_fields)

# RoCE write and ack
write_req_pkt_num = math.ceil(write_size / roce.mtu())
roce.recv_pkts(write_req_pkt_num)

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteImm), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# RoCE write imm and ack
sg = SG(pos_in_mr = 0, length = 0, lkey = mr.lkey())
sr = SendWR(
    opcode = WR_OPCODE.RDMA_WRITE_WITH_IMM,
    sgl = sg,
    # rmt_va = dst_va,
    # rkey = dst_rkey,
    send_flags = SEND_FLAGS.SIGNALED,
    imm_data_or_inv_rkey = 0x1234,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, 'cqe should exist'
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 0
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.SUCCESS

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
sg = SG(pos_in_mr = POS_IN_MR, length = 8, lkey = mr.lkey())
sr = SendWR(
    opcode = WR_OPCODE.ATOMIC_CMP_AND_SWP,
    sgl = sg,
    rmt_va = dst_va,
    rkey = dst_rkey,
    compare_add = 0,
    swap = 1,
)
qp.post_send(sr)
qp.process_one_sr()
# TODO: soft-roce failed to ack atomic operation
# roce.recv_pkts(1)
# cqe = qp.poll_cq()
# assert cqe is not None, 'cqe should exist'
# assert cqe.local_qpn() == qp.qpn()
# assert cqe.sqpn() == dst_qpn
# assert cqe.len() == sg.len()
# assert cqe.op() == WC_OPCODE.ATOMIC_CMP_AND_SWP
# assert cqe.status() == WC_STATUS.SUCCESS

# Exchange atomic done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicDone), peer_addr)
print(struct.unpack('<i', exch_data))

udp_sock.close()
