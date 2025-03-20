# settings.py

# File paths
PCAP_FILE = "pcaps/test.pcap"  # Default pcap file for testing

# ML model files
MODEL = "pickles/XGB_model.pkl"
ENCODER = "pickles/encoder.pkl"
SCALER = "pickles/scaler.pkl"

# Features to extract from packets
# Adjust these to match the features your model was trained on
FEATURES = [
    'frame.len',
    'ip.len',
    'ip.flags',
    'ip.ttl',
    'tcp.len',
    'tcp.ack',
    'tcp.flags',
    'tcp.window_size',
    'udp.length',
    'http.request.method',
    'http.referer',
    'http.request.version',
    'dns.qry.name.len',
    'mqtt.conack.flags',
    'mqtt.protoname',
    'mqtt.topic'
]

# Network settings
HOST = 'localhost'  # Listen on all interfaces
PORT = 3630       # Port to listen on

# Authentication settings / globals
global CLIENTS
# format: token : user id
CLIENTS = {"token":"user1"}

# Packet forwarding settings
INTERFACE = "eth0"         # Interface to monitor
FORWARD_INTERFACE = "eth1"  # Interface to forward clean packets

# IDS/IPS mode
IDS_MODE = True  # True for IDS (detection only), False for IPS (detection and blocking)