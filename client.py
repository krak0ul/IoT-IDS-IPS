#!/usr/bin/env python
import json
import base64
from scapy.all import rdpcap
from websockets.sync.client import connect


packets = rdpcap('pcaps/unit.pcap')

HOST = 'localhost'    # The remote host
PORT = '3630'              # The same port as used by the server
CLIENT_ID = 0       # unique identifier for each client
packet_id = 0


def create_json(client_id, packet_id, raw_bytes):
    base64_data = base64.b64encode(raw_bytes)
    # here cid == client ID and pid == packet ID
    json_object = {"cid" : client_id, "pid" : packet_id, "data" : base64_data.decode('utf-8')}
    return json.dumps(json_object)


def open_connection():
    uri = "ws://" + HOST + ":" + PORT
    with connect(uri) as websocket:
        for pkt in packets:
            raw_bytes = bytes(pkt)
            json_pkt = create_json(CLIENT_ID, packet_id, raw_bytes)

            websocket.send(json_pkt)

            ack = websocket.recv()
            print(f"<<< {ack}")

if __name__ == "__main__":
    open_connection()