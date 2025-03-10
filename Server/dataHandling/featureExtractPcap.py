import sys
from scapy.all import rdpcap, IPv6
import pyshark as ps
import pandas as pd


file_name = 'pcaps/test.pcap'


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    packets = ps.FileCapture(input_file=file_name)

    for pkt in packets:
        # discard IPv6 packets
        if (hasattr(pkt, 'eth')):
            if (pkt.eth.type == '0x86dd'):
                print('IPV6 PACKET')
                pass

            else:
                pkt.pretty_print()
                feature_extraction(pkt)
        else:
            pass
        

def feature_extraction(pkt):
    """
    Extract features from a raw packet. The features is the same we trained our model with.
    """
    features = ['arp.opcode', 'arp.hw.size', 'icmp.checksum', 'icmp.seq_le', 'icmp.unused', 'http.content_length', 'http.request.method', 'http.referer', 'http.request.version', 'http.response', 'http.tls_port', 'tcp.ack', 'tcp.ack_raw', 'tcp.checksum', 'tcp.connection.fin', 'tcp.connection.rst', 'tcp.connection.syn', 'tcp.connection.synack', 'tcp.flags', 'tcp.flags.ack', 'tcp.len', 'tcp.seq', 'udp.stream', 'udp.time_delta', 'dns.qry.name', 'dns.qry.name.len', 'dns.qry.qu', 'dns.qry.type', 'dns.retransmission', 'dns.retransmit_request', 'dns.retransmit_request_in', 'mqtt.conack.flags', 'mqtt.conflag.cleansess', 'mqtt.conflags', 'mqtt.hdrflags', 'mqtt.len', 'mqtt.msg_decoded_as', 'mqtt.msgtype', 'mqtt.proto_len', 'mqtt.protoname', 'mqtt.topic', 'mqtt.topic_len', 'mqtt.ver', 'mbtcp.len', 'mbtcp.trans_id', 'mbtcp.unit_id']
    pkt_features = []

    for feature in features:
        # print(feature)
        feature_value = get_attr(pkt, feature)
        pkt_features.append(feature_value)

    print(pkt_features)
    pkt_features_list = [pkt_features]      # needs to be a nested list to go in the dataFrame
    df = pd.DataFrame(data=[pkt_features], columns=features)
    print(df.head())


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
            print(attr_str + ': ' + str(attr))
            return attr        
        except:
            return 0

    


if __name__ == '__main__':
    process_pcap(file_name)
    sys.exit(0)