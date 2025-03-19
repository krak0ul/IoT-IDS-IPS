# Echo client program
import socket
import json
import base64
from scapy.all import rdpcap


packets = rdpcap('pcaps/unit.pcap')

HOST = 'localhost'    # The remote host
PORT = 3630              # The same port as used by the server
CLIENT_ID = 0       # unique identifier for each client
packet_ID = 0

def create_json(client_id, packet_id, raw_bytes):
    base64_data = base64.b64encode(raw_bytes)
    # here cid == client ID and pid == packet ID
    json_pkt = {"cid" : client_id, "pid" : packet_id, "data" : base64_data}
    return json.dumps(json_pkt)

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