#!/usr/bin/env python
import json
import base64
from scapy.all import rdpcap
from websockets.sync.client import connect


packets = rdpcap('pcaps/unit.pcap')

HOST = 'localhost'    # The remote host
PORT = '3630'              # The same port as used by the server
CLIENT_ID = 0       # unique identifier for each client
PACKET_ID = 0


def create_json(raw_bytes):
    global PACKET_ID, CLIENT_ID
    base64_data = base64.b64encode(raw_bytes)
    # here cid == client ID and pid == packet ID
    json_object = {"cid" : CLIENT_ID, "pid" : PACKET_ID, "data" : base64_data.decode('utf-8')}
    print(PACKET_ID)
    PACKET_ID += 1
    return json.dumps(json_object)


def open_connection():
    uri = "ws://" + HOST + ":" + PORT
    with connect(uri) as websocket:
        for pkt in packets:
            for i in range(2):
                raw_bytes = bytes(pkt)
                json_pkt = create_json(raw_bytes)
            
                websocket.send(json_pkt)
                print(f"Sent packet {PACKET_ID}")
            # ack = websocket.recv()
            # print(f"<<< {ack}")
            websocket.send("poulet")
            websocket.send(json_pkt)
        websocket.close()
if __name__ == "__main__":
    open_connection()