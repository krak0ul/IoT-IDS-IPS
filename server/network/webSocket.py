# from settings import HOST, PORT 
import asyncio
import json
import base64
from websockets.exceptions import ConnectionClosedOK
from websockets.frames import CloseCode
from network.authentication import get_user
from dataHandling.modelAPI import pkt_processing
from settings import CLIENTS
HOST = 'localhost'       # listen on all interfaces
PORT = 3630     # open port 3630


def get_raw_pkt(json_object):
    b64_bytes = json_object["data"].encode('utf-8')
    return base64.b64decode(b64_bytes)

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
    

async def handler(websocket, scaler, encoder, model):
    pkt_recv = []
    try:
        while True:
            data = await websocket.recv()
            print("async")
            json_object = process_packet(data)
            if json_object:
                pkt_recv.append(json_object)
                print(get_raw_pkt(json_object))
            asyncio.create_task(pkt_processing(get_raw_pkt(json_object), scaler, encoder, model, json_object))
    except ConnectionClosedOK:
        print(f"packets received: {pkt_recv}\n\n")
        print("Client closed connection\n\n")