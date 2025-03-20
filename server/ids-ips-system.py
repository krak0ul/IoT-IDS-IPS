import os
import sys
import threading
import time
import argparse
from settings import *

# Check for root privileges (needed for packet forwarding)
if os.geteuid() != 0:
    print("This script requires root privileges for packet forwarding. Please run with sudo.")
    sys.exit(1)

def start_ids_server():
    """
    Start the IDS/IPS analysis server in a separate thread
    """
    from main import IDSServer
    
    server = IDSServer(
        host=HOST,
        port=PORT,
        features=FEATURES,
        model_pickle=MODEL,
        encoder_pickle=ENCODER,
        scaler_pickle=SCALER
    )
    
    print("[+] Starting IDS/IPS analysis server...")
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to initialize
    time.sleep(2)
    return server_thread

def start_packet_forwarder():
    """
    Start the packet forwarder in a separate thread
    """
    from packetForwarder.pktForwarder import PacketForwarder
    
    forwarder = PacketForwarder(
        interface=INTERFACE,
        dest_host=HOST if HOST == '0.0.0.0' else 'localhost',
        dest_port=PORT,
        forward_interface=FORWARD_INTERFACE
    )
    
    print("[+] Starting packet forwarder...")
    forwarder_thread = threading.Thread(target=forwarder.start)
    forwarder_thread.daemon = True
    forwarder_thread.start()
    return forwarder_thread

def start_network_forwarder():
    """
    Setup network forwarding using iptables
    """
    from network_utils import NetworkForwarder
    
    forwarder = NetworkForwarder(INTERFACE, FORWARD_INTERFACE)
    success = forwarder.setup_forwarding()
    
    if success:
        print("[+] Network forwarding set up successfully")
    else:
        print("[!] Failed to set up network forwarding")
    
    return forwarder

def main():
    parser = argparse.ArgumentParser(description="IoT Network IDS/IPS System")
    parser.add_argument('--test', action='store_true', help='Test using a PCAP file')
    parser.add_argument('--ids-only', action='store_true', help='Run only the IDS server without packet forwarding')
    parser.add_argument('--forward-only', action='store_true', help='Run only the packet forwarding')
    args = parser.parse_args()
    
    if args.test:
        from main import test_with_pcap
        test_with_pcap()
        return
    
    threads = []
    forwarder = None
    
    try:
        # Start IDS server if requested
        if not args.forward_only:
            server_thread = start_ids_server()
            threads.append(server_thread)
        
        # Start packet and network forwarding if requested
        if not args.ids_only:
            forwarder = start_network_forwarder()
            forwarder_thread = start_packet_forwarder()
            threads.append(forwarder_thread)
        
        # Keep the main thread running
        print("[+] System running. Press Ctrl+C to exit.")
        while all(t.is_alive() for t in threads):
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        # Clean up
        if forwarder:
            forwarder.cleanup()
        print("[+] System stopped")

if __name__ == "__main__":
    main()