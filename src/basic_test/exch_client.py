import argparse
import socket
import struct

UDP_BUF_SIZE = 2048

parser = argparse.ArgumentParser(description="Input IP and port")
parser.add_argument("-s", action="store", dest="dst_ip")
parser.add_argument("-p", action="store", dest="dst_port", type=int, default=9527)
arg_res = parser.parse_args()

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv_bind_addr = ("0.0.0.0", arg_res.dst_port)
udp_sock.bind(srv_bind_addr)

dst_addr = (arg_res.dst_ip, arg_res.dst_port)
udp_sock.sendto(struct.pack("c", b"1"), dst_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack("<c", exch_data))

udp_sock.sendto(struct.pack("c", b"2"), dst_addr)
udp_sock.sendto(struct.pack("c", b"3"), dst_addr)


exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack("<c", exch_data))

exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack("<c", exch_data))

udp_sock.close()
