import socket
from pylibpcap.pcap import sniff

sock = socket.socket()
sock.connect(("10.0.2.2", 5000))

def handle(_, pkt):
    sock.sendall(pkt + b"\n") 

sniff("eth0", prn=handle, count=-1)