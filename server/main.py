import asyncio
import functools
from websockets.asyncio.server import serve

from settings import *

from dataHandling.dataPreparation import import_encoder, import_scaler
from dataHandling.modelAPI import import_model
from network.webSocket import handler
from network.authentication import token_auth

file_name = PCAP_FILE
model_pickle = MODEL
encoder_pickle = ENCODER
scaler_pickle = SCALER


async def main():
    scaler = import_scaler(scaler_pickle)
    encoder = import_encoder(encoder_pickle)
    model = import_model(model_pickle)

    async with serve(functools.partial(handler, scaler=scaler, encoder=encoder, model=model), HOST, PORT, process_request=token_auth) as server:
        await server.serve_forever()



if __name__ == "__main__":
    asyncio.run(main())