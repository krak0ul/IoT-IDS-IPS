# from settings import HOST, PORT 

import asyncio
import json
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosedOK
HOST = 'localhost'       # listen on all interfaces
PORT = 3630     # open port 3630
CLIENTS = set()

def decode_json(json_pkt):
    return json.loads(json_pkt)


def process_packet(data):
    try:
        json_object = decode_json(data)
        print(f"<<< {json_object}")
        return json_object

    except ValueError:
        print(f"Data: {data}")
        return None

async def process_socket(websocket):
    pkt_recv = []
    
    try:
        while True:
            data = await websocket.recv()
        
            json_object = process_packet(data)
            if json_object:
                pkt_recv.append(json_object)

            print(f"packets received: {pkt_recv}\n\n")
    except ConnectionClosedOK:
        print("Client closed connection")
        
async def main():
    async with serve(process_socket, HOST, PORT) as server:
        await server.serve_forever()



if __name__ == "__main__":
    asyncio.run(main())