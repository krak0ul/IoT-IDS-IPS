import json
import sys
import base64
from scapy.all import rdpcap, sniff
from websockets.sync.client import connect


HOST = 'localhost'    # The remote host
PORT = '3630'              # The same port as used by the server
INTERFACE = "eth0"    
CLIENT_ID = 0       # unique identifier for each client
PACKET_ID = 0
TOKEN = "token"


def create_json(raw_bytes, CLIENT_ID):
    global PACKET_ID
    base64_data = base64.b64encode(raw_bytes)
    # here cid == client ID and pid == packet ID
    json_object = {"cid" : CLIENT_ID, 
                   "pid" : PACKET_ID, 
                   "data" : base64_data.decode('utf-8')
                   }
    PACKET_ID += 1
    return json.dumps(json_object)


def open_connection_pcap(pcap):
    packets = rdpcap(pcap)
    uri = f"ws://{HOST}:{PORT}?token={TOKEN}"

    with connect(uri) as websocket:
        for pkt in packets:
            raw_bytes = bytes(pkt)
            json_pkt = create_json(raw_bytes, CLIENT_ID)
        
            websocket.send(json_pkt)
            print(f"Sent packet {PACKET_ID}")

        websocket.close()


def open_connection_sniff(INTERFACE):
    uri = f"ws://{HOST}:{PORT}?token={TOKEN}"
    with connect(uri) as websocket:

        def handle_pkt(pkt):
            raw_bytes = bytes(pkt)
            json_pkt = create_json(raw_bytes, CLIENT_ID)
        
            websocket.send(json_pkt)
            print(f"Sent packet {PACKET_ID}")

        sniff(iface=INTERFACE, prn=handle_pkt, store=False)
        websocket.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            print("\nWelcome to your Favourite IDS tool! \n\n\nUse option -h or --help to display this message.\n")
            print("Run the Client app with either one of the following options to send traffic to the IDS server:\n")
            print("Option -f or --forward < interface > will forward all traffic going through a specific interface.\n")
            print("Option -p or --pcap-file < file > will send all the packets in the pcap file.\n")
        
        elif sys.argv[1] == '-f' or sys.argv[1] == '--forward' or sys.argv[1] == '-p' or sys.argv[1] == '--pcap-file':
            print(f"Invalid number of arguments for option {sys.argv[1]}.")
        else:
            print(f"Invalid option {sys.argv[1]}\nUse option -h or --help to display the help message. ")

    elif len(sys.argv) == 3:
        if sys.argv[1] == '-p' or sys.argv[1] == '--pcap-file':
            print(sys.argv[2])
            token = open_connection_pcap(str(sys.argv[2]))

        elif sys.argv[1] == '-f' or sys.argv[1] == '--forward':
            open_connection_sniff(str(sys.argv[2]))
        else:
            print(f"Invalid option {sys.argv[1]}\nUse option -h or --help to display the help message. ")
    else:
        print(f"Invalid option\nUse option -h or --help to display the help message. ")
