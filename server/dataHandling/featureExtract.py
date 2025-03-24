import pyshark as ps
import pandas as pd
from scapy.all import rdpcap


def open_pcap(file_name):
    """
    for testing purposes - returns a pyshark object of all packets in a pcap
    """
    print('Opening {}...'.format(file_name))
    return ps.FileCapture(input_file=file_name)

def pcap_to_raw(file_name):
    """
    for testing purposes - put packets as raw bytes in buffer
    """
    try:
        raw_packets = rdpcap(file_name)
        pkt_buffer = []
        for pkt in raw_packets:
            pkt_buffer.append(bytes(pkt))
        # print(pkt_buffer)
        return pkt_buffer
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return []


def format_raw_packets(pkt_buffer):
    """
    Formats raw byte packets into pyshark Packet objects.
    """
    capture = ps.InMemCapture()
    # capture.set_debug()
    packets = capture.parse_packets(pkt_buffer)
    # print(packets)
    return packets

def format_raw_packet(pkt):
    """
    Formats raw byte packets into pyshark Packet objects.
    """
    capture = ps.InMemCapture()
    # capture.set_debug()
    packets = capture.parse_packet(pkt)
    # print(packets)
    return packets

def filter_packets(packets):
    """
    Goes through a list of packets and ignores all IPv6 packets.
    """
    filtered_pkts = []
    for pkt in packets:
        # print(pkt.pretty_print())
        # only keep packets that have an ethernet layer
        if (hasattr(pkt, 'eth')):
            # discard IPv6 packets
            if (pkt.eth.type == '0x86dd'):
                print('IPV6 PACKET - Ignoring packet')
                pass

            else:
                # pkt.pretty_print()
                filtered_pkts.append(pkt)
                # print(pkt)
        else:
            # print("No Ether layer")
            pass
    # print(filtered_pkts)
    return filtered_pkts
        
def filter_packet(pkt):
    """
    Checks if packet is IPv6, and returns packet if not.
    """
    # only keep packets that have an ethernet layer
    if (hasattr(pkt, 'eth')):
        # discard IPv6 packets
        if (pkt.eth.type == '0x86dd'):
            print('IPV6 PACKET - Ignoring packet\n')
            return
        else:
            # pkt.pretty_print()
            return pkt
            # print(pkt)
    else:
        # print("No Ether layer")
        return

def feature_extraction(pkt, features):
    """
    Extract features from a raw packet. The features are the same we trained our model with.
    """
    pkt_features = []

    for feature in features:
        # print(feature)
        feature_value = get_attr(pkt, feature)
        pkt_features.append(feature_value)

    return pkt_features
    



def convert_value(attr_str, raw_value):
    """
    Convert a raw value using a dictionary of conversion mappings.
    First, if the raw value is a hexadecimal string, it is converted to an integer.
    Then, the conversion function defined for attr_str in the dictionary is applied.
    If no mapping exists, an attempt is made to convert the value using pd.to_numeric.
    If conversion fails, returns 0 (or pd.NA for hex conversion errors).
    """
    # Convert hexadecimal string values to int
    if isinstance(raw_value, str) and raw_value.startswith('0x'):
        try:
            raw_value = int(raw_value, 16)
        except ValueError:
            return pd.NA
    
    # Define the mapping from field names to their conversion functions
    conversion_mapping = {
        "arp.opcode": float,
        "arp.hw.size": float,
        "icmp.checksum": float,
        "icmp.seq_le": float,
        "icmp.unused": float,
        "http.content_length": float,
        "http.request.method": str,
        "http.referer": str,
        "http.request.version": str,
        "http.response": float,
        "http.tls_port": float,
        "tcp.ack": float,
        "tcp.ack_raw": float,
        "tcp.checksum": float,
        "tcp.connection.fin": float,
        "tcp.connection.rst": float,
        "tcp.connection.syn": float,
        "tcp.connection.synack": float,
        "tcp.flags": float,
        "tcp.flags.ack": float,
        "tcp.len": float,
        "tcp.seq": float,
        "udp.stream": float,
        "udp.time_delta": float,
        "dns.qry.name": float,
        "dns.qry.name.len": str,
        "dns.qry.qu": float,
        "dns.qry.type": float,
        "dns.retransmission": float,
        "dns.retransmit_request": float,
        "dns.retransmit_request_in": float,
        "mqtt.conack.flags": str,
        "mqtt.conflag.cleansess": float,
        "mqtt.conflags": float,
        "mqtt.hdrflags": float,
        "mqtt.len": float,
        "mqtt.msg_decoded_as": float,
        "mqtt.msgtype": float,
        "mqtt.proto_len": float,
        "mqtt.protoname": str,
        "mqtt.topic": str,
        "mqtt.topic_len": float,
        "mqtt.ver": float,
        "mbtcp.len": float,
        "mbtcp.trans_id": float,
        "mbtcp.unit_id": float
    }
    
    conv_func = conversion_mapping.get(attr_str)
    
    if conv_func is not None:
        try:
            return conv_func(raw_value)
        except Exception as e:
            print(f"Conversion failed for {attr_str} with value {raw_value}: {e}")
            return 0
    else:
        # Fallback: try to convert using pandas' numeric conversion
        try:
            return pd.to_numeric(raw_value)
        except Exception:
            return raw_value



def get_attr(pkt, attr_str):
    """
    Gets attribute from a packet object given a dot-separated string.
    If any attribute in the chain is missing, return 0.
    This is required due to a bug in PyShark that gives error 'AttributeError'
    """
    # first field should be the packet layer being parsed
    fields = attr_str.split('.')

    #if packet does not have the required layer
    if not hasattr(pkt, fields[0]):
        return 0
    else:
        # gets a dictionary of all fields of that layer and searches for the attribute
        try: 
            # dirty try - except is temporary solution because some protocols don't always use all attributes
            field_obj = getattr(pkt, fields[0])._all_fields[attr_str]
            attr = field_obj.show
            # print("value:")
            # print(attr)
            # print(type(attr))
            # print(f" conv val: {convert_value(attr_str, attr)}")
            # print(f" conv val type: {type(convert_value(attr_str, attr))}")
            # print(attr_str + ': ' + str(attr))
            return convert_value(attr_str, attr)        
        except:
            return 0


def extract_packets(packets, features):
    """
    Parses a list of pyshark packets to extract specified features in each packet.
    Returns a pandas DataFrame with the features as columns and each non-IPv6 packet as a row.
    """
    filtered_pkts = filter_packets(packets)
    print(filtered_pkts)
    if not filtered_pkts:
        # print("no packets to predict")
        return
    pkt_features_list = [] 

    for pkt in filtered_pkts:
        pkt_features = feature_extraction(pkt, features)
        pkt_features_list.append(pkt_features)
    
    df = pd.DataFrame(data=pkt_features_list, columns=features)
    # print(df)
    return df

def extract_packet(packet, features):
    """
    Parses a single pyshark packet to extract specified features.
    Returns a pandas DataFrame with the features as columns and the non-IPv6 packet as a row.
    """
    filtered_pkt = filter_packet(packet)
    # print(filtered_pkt)
    if not filtered_pkt:
        # print("no packet to predict")
        return

    pkt_features = feature_extraction(filtered_pkt, features)
    print(f"packet features: {pkt_features}")
    df = pd.DataFrame(data=[pkt_features], columns=features)
    # print(df)
    return df