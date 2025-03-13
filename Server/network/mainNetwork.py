import recv

# packet buffer
pkt_recv = []

def main():
    pkt_recv.append(recv.newSocket())
    recv.prt_pkt_recv(pkt_recv)

if __name__ == '__main__':
    main()