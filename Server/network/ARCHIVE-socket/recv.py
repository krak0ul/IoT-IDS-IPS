import socket
import json

HOST = ''       # listen on all interfaces
PORT = 3630     # open port 3630



def newSocket():
    # packet buffer
    pkt_recv = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        conn, addr = s.accept()

        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                
                if not data:
                    break
                
                conn.sendall(b'Packet received')

                # decode json if the received packet is in json format
                try:
                    json_object = decode_json(data)
                    print("Data: ", json_object)
                    pkt_recv.append(json_object)
                except ValueError:
                    print("Data: ", data)
    return  pkt_recv

def prt_pkt_recv(pkt_recv):
    for i in pkt_recv:
        print(i)

    return

def decode_json(json_pkt):
    json_object = json_pkt.decode('utf-8')
    return json.loads(json_object)