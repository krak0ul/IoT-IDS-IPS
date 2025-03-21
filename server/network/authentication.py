from uuid import uuid4
import urllib.parse
import http
from settings import CLIENTS


def gen_token(user):
    token = uuid4().hex
    CLIENTS[token] = user
    print(CLIENTS)
    return token

def del_token(token):
    try:
        return CLIENTS.pop(token)
    
    except KeyError:
        try:
            token = get_token(token)
            CLIENTS.pop(token)
            return token
        
        except KeyError:
            return

def get_user(token):
    """Find user authenticated by token or return None."""
    return CLIENTS.get(token)

def get_token(user):
    for token in CLIENTS:
        if CLIENTS[token] == user:
            return token
        else:
            return 

def get_query_param(path, key):
    query = urllib.parse.urlparse(path).query
    params = urllib.parse.parse_qs(query)
    values = params.get(key, [])
    if len(values) == 1:
        return values[0]

async def token_auth(connection, request):
    """
    Authentication by passing the client token as a query parameter of the http packet
    """
    token = get_query_param(request.path, "token")
    # print(token)
    if token is None:
        return connection.respond(http.HTTPStatus.UNAUTHORIZED, "Missing token\n")

    user = get_user(token)
    # print(user)
    if user is None:
        return connection.respond(http.HTTPStatus.UNAUTHORIZED, "Invalid token\n")

    connection.username = user