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
            print('IPV6 PACKET - Ignoring packet')
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

    print(f"feature list {pkt_features}")
    print(f"pkt features: {pkt_features}")
    return pkt_features
    


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
            attr = getattr(pkt, fields[0])._all_fields[attr_str]
            # print(attr_str + ': ' + str(attr))
            return attr        
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
        print("no packets to predict")
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
    print(filtered_pkt)
    if not filtered_pkt:
        print("no packet to predict")
        return
    pkt_features_list = [] 

    pkt_features = feature_extraction(filtered_pkt, features)
    
    df = pd.DataFrame(data=[pkt_features], columns=features)
    # print(df)
    return df