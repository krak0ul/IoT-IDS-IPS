# from settings import HOST, PORT 

import asyncio
import json
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosedOK
from websockets.frames import CloseCode
from server.network.authentication import get_user, token_auth
from server.settings import CLIENTS
HOST = 'localhost'       # listen on all interfaces
PORT = 3630     # open port 3630




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

async def first_message_handler(websocket):
    """Handler that sends credentials in the first WebSocket message."""
    token = await websocket.recv()
    user = get_user(token)
    if user is None:
        await websocket.close(CloseCode.INTERNAL_ERROR, "authentication failed")
        return

    websocket.username = user
    await handler(websocket)
    

async def handler(websocket):
    pkt_recv = []
    try:
        while True:
            data = await websocket.recv()
        
            json_object = process_packet(data)
            if json_object:
                pkt_recv.append(json_object)

    except ConnectionClosedOK:
        print(f"packets received: {pkt_recv}\n\n")
        print("Client closed connection\n\n")


async def main():
    async with serve(handler, HOST, PORT, process_request=token_auth) as server:
        await server.serve_forever()



if __name__ == "__main__":
    asyncio.run(main())