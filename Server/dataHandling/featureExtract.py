# dataHandling/featureExtract.py
import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, Ether
import socket
import struct

def pcap_to_raw(pcap_file):
    """
    Reads a pcap file and returns a list of raw packet data
    """
    try:
        packets = rdpcap(pcap_file)
        raw_packets = [bytes(packet) for packet in packets]
        return raw_packets
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return []

def format_raw(raw_packets):
    """
    Converts raw packet bytes back to scapy packets
    """
    formatted_packets = []
    for raw_packet in raw_packets:
        try:
            packet = Ether(raw_packet)
            formatted_packets.append(packet)
        except Exception as e:
            print(f"Error formatting packet: {e}")
    return formatted_packets

def extract_packet_features(packet, features):
    """
    Extract features from a single packet
    """
    packet_features = {}
    
    # Extract Ethernet features
    if 'eth_src' in features and Ether in packet:
        packet_features['eth_src'] = packet[Ether].src
    if 'eth_dst' in features and Ether in packet:
        packet_features['eth_dst'] = packet[Ether].dst
    if 'eth_type' in features and Ether in packet:
        packet_features['eth_type'] = packet[Ether].type
        
    # Extract IP features
    if IP in packet:
        if 'ip_src' in features:
            packet_features['ip_src'] = packet[IP].src
        if 'ip_dst' in features:
            packet_features['ip_dst'] = packet[IP].dst
        if 'ip_proto' in features:
            packet_features['ip_proto'] = packet[IP].proto
        if 'ip_len' in features:
            packet_features['ip_len'] = packet[IP].len
        if 'ip_ttl' in features:
            packet_features['ip_ttl'] = packet[IP].ttl
        if 'ip_flags' in features:
            packet_features['ip_flags'] = packet[IP].flags
    else:
        # Fill with NaN for IP features if they're in the feature list
        for feature in features:
            if feature.startswith('ip_') and feature not in packet_features:
                packet_features[feature] = np.nan
    
    # Extract TCP features
    if TCP in packet:
        if 'tcp_sport' in features:
            packet_features['tcp_sport'] = packet[TCP].sport
        if 'tcp_dport' in features:
            packet_features['tcp_dport'] = packet[TCP].dport
        if 'tcp_flags' in features:
            packet_features['tcp_flags'] = packet[TCP].flags
        if 'tcp_window' in features:
            packet_features['tcp_window'] = packet[TCP].window
    else:
        # Fill with NaN for TCP features if they're in the feature list
        for feature in features:
            if feature.startswith('tcp_') and feature not in packet_features:
                packet_features[feature] = np.nan
    
    # Extract UDP features
    if UDP in packet:
        if 'udp_sport' in features:
            packet_features['udp_sport'] = packet[UDP].sport
        if 'udp_dport' in features:
            packet_features['udp_dport'] = packet[UDP].dport
        if 'udp_len' in features:
            packet_features['udp_len'] = packet[UDP].len
    else:
        # Fill with NaN for UDP features if they're in the feature list
        for feature in features:
            if feature.startswith('udp_') and feature not in packet_features:
                packet_features[feature] = np.nan
    
    # Calculate packet size
    if 'packet_size' in features:
        packet_features['packet_size'] = len(bytes(packet))
    
    # Fill missing features with NaN
    for feature in features:
        if feature not in packet_features:
            packet_features[feature] = np.nan
    
    return packet_features

def extract_packets(packets, features):
    """
    Extract features from all packets and return a DataFrame
    """
    packet_data = []
    
    for packet in packets:
        packet_features = extract_packet_features(packet, features)
        packet_data.append(packet_features)
    
    # Convert to DataFrame
    df = pd.DataFrame(packet_data)
    
    # Ensure all requested features are in the DataFrame
    for feature in features:
        if feature not in df.columns:
            df[feature] = np.nan
    
    # Ensure DataFrame has only the requested features and in the right order
    df = df[features]
    
    return df