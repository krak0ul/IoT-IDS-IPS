import socket

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
                print("Data: ", repr(data))
                pkt_recv.append(data)
    return  pkt_recv

def prt_pkt_recv(pkt_recv):
    for i in pkt_recv:
        print(i)
    return