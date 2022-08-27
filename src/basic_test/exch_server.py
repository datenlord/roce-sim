import argparse
import socket
import struct

parser = argparse.ArgumentParser(description="Input IP and port")
parser.add_argument("-p", action="store", dest="src_port", type=int, default=9527)
arg_res = parser.parse_args()

SRC_PORT = arg_res.src_port
UDP_BUF_SIZE = 2048

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv_bind_addr = ("0.0.0.0", SRC_PORT)
udp_sock.bind(srv_bind_addr)

exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack("<c", exch_data))
udp_sock.sendto(struct.pack("c", b"a"), peer_addr)
udp_sock.sendto(struct.pack("c", b"b"), peer_addr)
udp_sock.sendto(struct.pack("c", b"c"), peer_addr)


exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack("<c", exch_data))

exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack("<c", exch_data))

udp_sock.close()
