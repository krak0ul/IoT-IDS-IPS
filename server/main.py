import sys
import asyncio
import functools
from websockets.asyncio.server import serve

from settings import MODEL, ENCODER, SCALER, HOST, PORT

from dataHandling.dataPreparation import import_encoder, import_scaler
from dataHandling.modelAPI import import_model
from network.webSocket import handler
from network.authentication import token_auth, gen_token, del_token

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
    if len(sys.argv) == 1:
        asyncio.run(main())


    elif len(sys.argv) == 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            print("\nWelcome to your Favourite IDS tool! \n\n\nUse option -h or --help to display this message.\n")
            print("Run the app with no option to start the IDS.\n")
            print("Option -t or --gen-token < UNAME | UID > will create a new authentication token and add it to the authorized clients database\n")
            print("Option -d or --del-token < UNAME | UID | token > will delete the client's name and token from the clients database\n")
        
        elif sys.argv[1] == '-t' or sys.argv[1] == '--gen-token' or sys.argv[1] == '-d' or sys.argv[1] == '--del-token':
            print(f"Invalid number of arguments for option {sys.argv[1]}.")
        else:
            print(f"Invalid option {sys.argv[1]}\nUse option -h or --help to display the help message. ")

    elif len(sys.argv) == 3:
        if sys.argv[1] == '-t' or sys.argv[1] == '--gen-token':
            token = gen_token(str(sys.argv[2]))
            print(f"Your token is: {token}\nStore it safely.")

        elif sys.argv[1] == '-d' or sys.argv[1] == '--del-token':
            client = del_token(str(sys.argv[2]))
            if client:
                print(f"Deleted {client} : {sys.argv[2]} from the clients database")
            else:
                print(f"Client or token {sys.argv[2]} not found in clients database.")
        else:
            print(f"Invalid option {sys.argv[1]}\nUse option -h or --help to display the help message. ")
    else:
        print(f"Invalid option\nUse option -h or --help to display the help message. ")