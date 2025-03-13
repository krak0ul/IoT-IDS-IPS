# Echo client program
import socket
import pyshark as ps

from scapy.all import rdpcap


packets = rdpcap('pcaps/unit.pcap')

HOST = 'localhost'    # The remote host
PORT = 3630              # The same port as used by the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    for pkt in packets:
        raw_bytes = bytes(pkt)

        print(type(pkt))
        s.sendall(raw_bytes)
        data = s.recv(1024)

        print('Ack Received', repr(data))
    
    s.sendall(b'Bye, world')

    s.close()