import pyshark
import socket
import json
import threading
import pickle
import os
import time

# Configuration
DEST_HOST = 'localhost'  # IDS/IPS server address
DEST_PORT = 3630         # IDS/IPS server port
INTERFACE = "eth0"       # Interface to monitor
FORWARD_INTERFACE = "eth1"  # Interface to forward clean packets to

# Enable/disable features
ENABLE_IDS_MODE = True   # Analyze but don't block (True = IDS, False = IPS)
ENABLE_LOGGING = True

class PacketForwarder:
    def __init__(self, interface, dest_host, dest_port, forward_interface):
        self.interface = interface
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.forward_interface = forward_interface
        self.blocked_ips = set()  # IPs currently being blocked
        self.lock = threading.Lock()
        
    def serialize_packet(self, packet):
        """
        Convert pyshark packet to a serializable format with metadata
        """
        packet_dict = {
            'raw_bytes': bytes(packet),
            'timestamp': float(packet.sniff_time.timestamp()) if hasattr(packet, 'sniff_time') else time.time()
        }
        
        # Add layer-specific information if available
        if hasattr(packet, 'ip'):
            packet_dict['src_ip'] = packet.ip.src
            packet_dict['dst_ip'] = packet.ip.dst
            packet_dict['proto'] = packet.ip.proto
        
        if hasattr(packet, 'tcp'):
            packet_dict['src_port'] = packet.tcp.srcport
            packet_dict['dst_port'] = packet.tcp.dstport
            packet_dict['tcp_flags'] = packet.tcp.flags if hasattr(packet.tcp, 'flags') else 0
        elif hasattr(packet, 'udp'):
            packet_dict['src_port'] = packet.udp.srcport
            packet_dict['dst_port'] = packet.udp.dstport
            
        return pickle.dumps(packet_dict)
    
    def process_packet(self, packet):
        """
        Process a packet: send to IDS/IPS server and handle the response
        """
        try:
            # Skip packets that are from our own socket communication
            if hasattr(packet, 'tcp') and (
                int(packet.tcp.srcport) == self.dest_port or 
                int(packet.tcp.dstport) == self.dest_port
            ):
                return
                
            # Serialize the packet with metadata
            serialized_data = self.serialize_packet(packet)
            
            # Send to IDS/IPS server for analysis
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.dest_host, self.dest_port))
                s.sendall(serialized_data)
                
                # Receive the analysis result
                response = s.recv(4096)
                try:
                    response_data = json.loads(response.decode('utf-8'))
                    
                    if ENABLE_LOGGING:
                        print(f"IDS/IPS analysis: {response_data}")
                    
                    # Handle malicious packets
                    if response_data.get('is_malicious', False):
                        if hasattr(packet, 'ip'):
                            with self.lock:
                                self.blocked_ips.add(packet.ip.src)
                            print(f"⚠️ Detected malicious traffic from {packet.ip.src}. {response_data.get('reason', '')}")
                            
                            if not ENABLE_IDS_MODE:  # In IPS mode, don't forward malicious packets
                                return
                except json.JSONDecodeError:
                    print(f"Error decoding response: {response}")
                
                # Forward the original packet if in IDS mode or if not blocked in IPS mode
                if hasattr(packet, 'ip'):
                    is_blocked = packet.ip.src in self.blocked_ips
                    should_forward = ENABLE_IDS_MODE or not is_blocked
                    
                    if should_forward:
                        # Note: PyShark can't easily forward packets directly
                        # We would need to use a different approach like OS-level packet forwarding
                        # This is a placeholder
                        if ENABLE_LOGGING:
                            print(f"Would forward packet from {packet.ip.src} to {packet.ip.dst}")
                        # In a real implementation, we might use something like:
                        # os.system(f"iptables -t nat -A PREROUTING -s {packet.ip.src} -j ACCEPT")
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start(self):
        """
        Start sniffing packets on the interface
        """
        print(f"Starting packet forwarder on interface {self.interface}...")
        print(f"Forwarding to IDS/IPS at {self.dest_host}:{self.dest_port}")
        print(f"Mode: {'IDS (Detection Only)' if ENABLE_IDS_MODE else 'IPS (Detection and Prevention)'}")
        
        # Start capturing
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            for packet in capture.sniff_continuously():
                self.process_packet(packet)
        except KeyboardInterrupt:
            print("Stopping packet capture...")
        except Exception as e:
            print(f"Error in packet capture: {e}")

def forward_using_iptables(blocked_ips, forward_interface):
    """
    Alternative approach: Use iptables for packet forwarding
    This would be implemented in a real system but is out of scope for this example
    """
    # Example: Forward all traffic except blocked IPs
    os.system(f"iptables -t nat -A POSTROUTING -o {forward_interface} -j MASQUERADE")
    for ip in blocked_ips:
        os.system(f"iptables -A FORWARD -s {ip} -j DROP")

if __name__ == "__main__":
    forwarder = PacketForwarder(
        interface=INTERFACE,
        dest_host=DEST_HOST,
        dest_port=DEST_PORT,
        forward_interface=FORWARD_INTERFACE
    )
    forwarder.start()