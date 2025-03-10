import pyshark as ps
import pandas as pd


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



def pcap_to_df(file_name, features):
    """
    Parses a provided pcap file to extract specified features in each packet.
    Returns a pandas DataFrame with the features as columns and each non-IPv6 packet as a row.
    """
    packets = open_pcap(file_name)
    filtered_pkts = filter_packets(packets)
    
    pkt_features_list = [] 

    for pkt in filtered_pkts:
        pkt_features = feature_extraction(pkt, features)
        pkt_features_list.append(pkt_features)
        
    df = pd.DataFrame(data=pkt_features_list, columns=features)
    # print(df)
    return df
