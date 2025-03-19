# from settings import HOST, PORT 

import asyncio
import json
from websockets.asyncio.server import serve

HOST = 'localhost'       # listen on all interfaces
PORT = 3630     # open port 3630


def decode_json(json_pkt):
    return json.loads(json_pkt)


async def hello(websocket):
    pkt_recv = []
    
    data = await websocket.recv()
    
    try:
        json_object = decode_json(data)
        print("<<< ", json_object)
        pkt_recv.append(json_object)

    except ValueError:
        print("Data: ", data)
        
    ack = 'Packet received'

    await websocket.send(ack)
    print(">>> ", ack)


async def main():
    async with serve(hello, HOST, PORT) as server:
        await server.serve_forever()



if __name__ == "__main__":
    asyncio.run(main())