import math
import socket
import struct
import logging
from roce_enum import *
from roce_v2 import *

MR_SIZE = 1024
MSG_SIZE = 720

DST_IP = '192.168.122.190'
SRC_IP = '192.168.122.238'
ROCE_PORT = 4791
DST_PORT = 9527
SRC_PORT = 6543
UDP_BUF_SIZE = 2048

S_VA = '0000556acaa2ea50'
#S_RKEY = '00000208'
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
#sg = SG(addr = mr.addr(), length = mr.len(), lkey = mr.lkey(), data = struct.pack(f'<{MR_SIZE}s', bytes('1234567890', 'ascii')))
#sge = SGE(addr = mr.addr(), length = mr.len(), lkey = mr.lkey(), data = struct.pack(f'<{MR_SIZE}s', bytes('1234567890', 'ascii')))
#sgl = SGL()
#sgl.append(sge)
#sr = SendWR(
#    opcode = WR_OPCODE.SEND,
#    send_flags = SEND_FLAGS.SIGNALED,
#    sgl = sg,
#)

# Connect to server
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_bind_addr = ('0.0.0.0', SRC_PORT)
udp_sock.bind(client_bind_addr)
srv_addr = (DST_IP, DST_PORT)
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
src_rkey = '{:08x}'.format(mr.rkey())
src_qpn = '{:08x}'.format(qp.qpn())
client_metadata = src_va + src_rkey + src_qpn + S_LID + S_GID
udp_sock.sendto(bytes.fromhex(client_metadata), peer_addr)

# Setup QP, post receive
sg = SG(pos_in_mr = POS_IN_MR, length = mr.len() - POS_IN_MR, lkey = mr.lkey())
rr = RecvWR(sgl = sg)
qp.post_recv(rr)
qp.modify_qp(qps = QPS.RTR, dgid = dst_gid, dst_qpn = dst_qpn) # dqpn should be integer

# Exchange receive ready
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', ReceiveReady), peer_addr)
print(struct.unpack('<i', exch_data))

qp.modify_qp(qps = QPS.RTS)

# Exchange send size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', SendSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, send_size = parsed_fields
print(f'send_size={send_size}')
print(parsed_fields)

# RoCE send and ack
send_req_pkt_num = math.ceil(send_size / roce.mtu())
roce.recv_pkts(send_req_pkt_num)
cqe = qp.poll_cq()
assert cqe is not None, 'cqe should exist'
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == mr.write_and_append_size()
assert cqe.op() == WC_OPCODE.SEND
assert cqe.status() == WC_STATUS.SUCCESS

# Exchange read size
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', ReadSize, -1), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
_, read_size = parsed_fields
print(parsed_fields)

# RoCE read and ack
sg = SG(pos_in_mr = POS_IN_MR, length = read_size, lkey = mr.lkey())
sr = SendWR(
   opcode = WR_OPCODE.RDMA_READ,
   sgl = sg,
   rmt_va = dst_va,
   rkey = dst_rkey,
   #send_flags = SEND_FLAGS.SIGNALED,
)
qp.post_send(sr)
read_resp_pkt_num = math.ceil(read_size / roce.mtu())
qp.process_one_sr()
roce.recv_pkts(read_resp_pkt_num)
cqe = qp.poll_cq()
assert cqe is not None, 'cqe should exist'
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
print(f'cqe.len()={cqe.len()} != sg.len()={sg.len()}, read_size={read_size}')
#assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.RDMA_READ
assert cqe.status() == WC_STATUS.SUCCESS

# Exchange write size
write_size = MSG_SIZE
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<iq', WriteSize, write_size), peer_addr)
parsed_fields = struct.unpack('<iq', exch_data)
print(parsed_fields)

# RoCE write and ack
sg = SG(pos_in_mr = POS_IN_MR, length = write_size, lkey = mr.lkey())
sr = SendWR(
   opcode = WR_OPCODE.RDMA_WRITE,
   sgl = sg,
   rmt_va = dst_va,
   rkey = dst_rkey,
   send_flags = SEND_FLAGS.SIGNALED,
)
qp.post_send(sr)
qp.process_one_sr()
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, 'cqe should exist'
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == sg.len()
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.SUCCESS

# Exchange write imm
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteImm), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# RoCE write imm and ack
qp.post_recv(rr)
roce.recv_pkts(1)
cqe = qp.poll_cq()
assert cqe is not None, 'cqe should exist'
assert cqe.local_qpn() == qp.qpn()
assert cqe.sqpn() == dst_qpn
assert cqe.len() == 0
assert cqe.op() == WC_OPCODE.RDMA_WRITE
assert cqe.status() == WC_STATUS.SUCCESS
assert cqe.imm_data_or_inv_rkey() is not None

# Exchange write done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', WriteDone), peer_addr)
parsed_fields = struct.unpack('<i', exch_data)
print(parsed_fields)

# Exchange atomic ready
mr.write(b'\x01\x00\x00\x00\x00\x00\x00\x00', pos = 8)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicReady), peer_addr)
print(struct.unpack('<i', exch_data))

# RoCE atomic and ack
roce.recv_pkts(1)
print(mr.read_all()[0:24])

# Exchange atomic done
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
udp_sock.sendto(struct.pack('<i', AtomicDone), peer_addr)
print(struct.unpack('<i', exch_data))

udp_sock.close()
