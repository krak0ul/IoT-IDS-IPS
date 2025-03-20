# settings.py

# File paths
PCAP_FILE = "pcaps/test.pcap"  # Default pcap file for testing

# ML model files
MODEL = "server/pickles/XGB_model.pkl"
ENCODER = "server/pickles/encoder.pkl"
SCALER = "server/pickles/scaler.pkl"

# Features to extract from packets
# Adjust these to match the features your model was trained on
global FEATURES
FEATURES = ['arp.opcode', 'arp.hw.size', 'icmp.checksum', 'icmp.seq_le', 'icmp.unused', 'http.content_length', 'http.request.method', 'http.referer', 'http.request.version', 'http.response', 'http.tls_port', 'tcp.ack', 'tcp.ack_raw', 'tcp.checksum', 'tcp.connection.fin', 'tcp.connection.rst', 'tcp.connection.syn', 'tcp.connection.synack', 'tcp.flags', 'tcp.flags.ack', 'tcp.len', 'tcp.seq', 'udp.stream', 'udp.time_delta', 'dns.qry.name', 'dns.qry.name.len', 'dns.qry.qu', 'dns.qry.type', 'dns.retransmission', 'dns.retransmit_request', 'dns.retransmit_request_in', 'mqtt.conack.flags', 'mqtt.conflag.cleansess', 'mqtt.conflags', 'mqtt.hdrflags', 'mqtt.len', 'mqtt.msg_decoded_as', 'mqtt.msgtype', 'mqtt.proto_len', 'mqtt.protoname', 'mqtt.topic', 'mqtt.topic_len', 'mqtt.ver', 'mbtcp.len', 'mbtcp.trans_id', 'mbtcp.unit_id']


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