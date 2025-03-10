import sys
import pyshark as ps
import pandas as pd


file_name = 'pcaps/test.pcap'
features = ['arp.opcode', 'arp.hw.size', 'icmp.checksum', 'icmp.seq_le', 'icmp.unused', 'http.content_length', 'http.request.method', 'http.referer', 'http.request.version', 'http.response', 'http.tls_port', 'tcp.ack', 'tcp.ack_raw', 'tcp.checksum', 'tcp.connection.fin', 'tcp.connection.rst', 'tcp.connection.syn', 'tcp.connection.synack', 'tcp.flags', 'tcp.flags.ack', 'tcp.len', 'tcp.seq', 'udp.stream', 'udp.time_delta', 'dns.qry.name', 'dns.qry.name.len', 'dns.qry.qu', 'dns.qry.type', 'dns.retransmission', 'dns.retransmit_request', 'dns.retransmit_request_in', 'mqtt.conack.flags', 'mqtt.conflag.cleansess', 'mqtt.conflags', 'mqtt.hdrflags', 'mqtt.len', 'mqtt.msg_decoded_as', 'mqtt.msgtype', 'mqtt.proto_len', 'mqtt.protoname', 'mqtt.topic', 'mqtt.topic_len', 'mqtt.ver', 'mbtcp.len', 'mbtcp.trans_id', 'mbtcp.unit_id']


def open_pcap(file_name):
    print('Opening {}...'.format(file_name))
    return ps.FileCapture(input_file=file_name)

def filter_packets(packets):
    filtered_pkts = []
    for pkt in packets:
        # only keep packets that have an ethernet layer
        if (hasattr(pkt, 'eth')):
            # discard IPv6 packets
            if (pkt.eth.type == '0x86dd'):
                # print('IPV6 PACKET')
                pass

            else:
                # pkt.pretty_print()
                filtered_pkts.append(pkt)
                # print(pkt)
        else:
            pass
    # print(filtered_pkts)
    return filtered_pkts
        

def feature_extraction(pkt, features):
    """
    Extract features from a raw packet. The features is the same we trained our model with.
    """
    pkt_features = []

    for feature in features:
        # print(feature)
        feature_value = get_attr(pkt, feature)
        pkt_features.append(feature_value)

    # print(pkt_features)
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



if __name__ == '__main__':
    packets = open_pcap(file_name)
    filtered_pkts = filter_packets(packets)
    
    pkt_features_list = [] 

    for pkt in filtered_pkts:
        pkt_features = feature_extraction(pkt, features)
        pkt_features_list.append(pkt_features)
        
    df = pd.DataFrame(data=pkt_features_list, columns=features)
    print(df)
    sys.exit(0)