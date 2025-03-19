import os
import subprocess
import threading
import time

class NetworkForwarder:
    """
    Helper class for handling network packet forwarding using iptables
    """
    def __init__(self, interface_in, interface_out):
        self.interface_in = interface_in
        self.interface_out = interface_out
        self.blocked_ips = set()
        self.lock = threading.Lock()
        
    def setup_forwarding(self):
        """
        Setup initial packet forwarding rules
        """
        try:
            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
                
            # Clear existing rules
            os.system('iptables -F')
            os.system('iptables -t nat -F')
            
            # Setup NAT
            os.system(f'iptables -t nat -A POSTROUTING -o {self.interface_out} -j MASQUERADE')
            
            # Allow forwarding
            os.system(f'iptables -A FORWARD -i {self.interface_in} -o {self.interface_out} -j ACCEPT')
            os.system(f'iptables -A FORWARD -i {self.interface_out} -o {self.interface_in} -m state --state RELATED,ESTABLISHED -j ACCEPT')
            
            print(f"Packet forwarding set up from {self.interface_in} to {self.interface_out}")
            return True
        except Exception as e:
            print(f"Error setting up packet forwarding: {e}")
            return False
    
    def block_ip(self, ip_address, duration=300):
        """
        Block traffic from a specific IP address for a specified duration
        
        Args:
            ip_address (str): The IP address to block
            duration (int): Duration in seconds to block the IP (default: 5 minutes)
        """
        with self.lock:
            if ip_address in self.blocked_ips:
                return False  # Already blocked
                
            try:
                # Add IP to block list
                self.blocked_ips.add(ip_address)
                
                # Block the IP
                os.system(f'iptables -A INPUT -s {ip_address} -j DROP')
                os.system(f'iptables -A FORWARD -s {ip_address} -j DROP')
                
                print(f"Blocked traffic from {ip_address} for {duration} seconds")
                
                # Start a timer to unblock after duration
                unblock_thread = threading.Thread(
                    target=self._unblock_after_timeout,
                    args=(ip_address, duration)
                )
                unblock_thread.daemon = True
                unblock_thread.start()
                
                return True
            except Exception as e:
                print(f"Error blocking IP {ip_address}: {e}")
                return False
    
    def _unblock_after_timeout(self, ip_address, duration):
        """
        Helper method to unblock an IP after a timeout
        """
        time.sleep(duration)
        self.unblock_ip(ip_address)
    
    def unblock_ip(self, ip_address):
        """
        Unblock traffic from a specific IP address
        """
        with self.lock:
            if ip_address not in self.blocked_ips:
                return False  # Not blocked
                
            try:
                # Remove from block list
                self.blocked_ips.remove(ip_address)
                
                # Unblock the IP
                os.system(f'iptables -D INPUT -s {ip_address} -j DROP')
                os.system(f'iptables -D FORWARD -s {ip_address} -j DROP')
                
                print(f"Unblocked traffic from {ip_address}")
                return True
            except Exception as e:
                print(f"Error unblocking IP {ip_address}: {e}")
                return False
    
    def cleanup(self):
        """
        Clean up forwarding rules when shutting down
        """
        try:
            # Clear all blocked IPs
            for ip in list(self.blocked_ips):
                self.unblock_ip(ip)
                
            # Disable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0')
                
            print("Network forwarding rules cleaned up")
            return True
        except Exception as e:
            print(f"Error cleaning up network rules: {e}")
            return False

# Example usage
if __name__ == "__main__":
    forwarder = NetworkForwarder("eth0", "eth1")
    forwarder.setup_forwarding()
    
    # Example: Block an IP for 60 seconds
    forwarder.block_ip("192.168.1.100", 60)
    
    try:
        # Keep running
        print("Press Ctrl+C to exit...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        forwarder.cleanup()