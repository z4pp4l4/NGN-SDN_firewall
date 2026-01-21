from scapy.all import sniff
import socket
import base64

HOST_IP = "172.17.0.1"
PORT = 5000


sock = socket.socket()
sock.connect((HOST_IP, PORT))

def send_packet(pkt):
    try:
        raw_bytes = bytes(pkt)
        encoded = base64.b64encode(raw_bytes).decode()
        sock.sendall((encoded + "\n").encode())
    except Exception as e:
        print("[SNIFFER] error sending packet:", e)

sniff(iface=["eth1", "eth2"], prn=send_packet, store=False)

