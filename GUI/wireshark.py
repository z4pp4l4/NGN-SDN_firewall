import socket

server = socket.socket()
server.bind(("0.0.0.0", 5000))
server.listen(1)

conn, _ = server.accept()

while True:
    data = conn.recv(9000)
    if not data:
        break
    print("Packet:", data)