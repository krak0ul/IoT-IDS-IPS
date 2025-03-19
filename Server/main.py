import sys
import threading
import socket
import pickle
import json
import pandas as pd
from settings import *
from dataHandling.featureExtract import extract_packets, format_raw, pcap_to_raw
from dataHandling.dataPreparation import prepareData, import_encoder, import_scaler
from dataHandling.modelAPI import import_model, prediction

# ML model configuration
file_name = PCAP_FILE
features = FEATURES
model_pickle = MODEL
encoder_pickle = ENCODER
scaler_pickle = SCALER

# Server configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 3630       # Port to listen on

class IDSServer:
    def __init__(self, host, port, features, model_pickle, encoder_pickle, scaler_pickle):
        self.host = host
        self.port = port
        self.features = features
        self.model_pickle = model_pickle
        self.encoder_pickle = encoder_pickle
        self.scaler_pickle = scaler_pickle
        
        # Load ML components
        print("Loading ML components...")
        self.model = import_model(self.model_pickle)
        self.scaler = import_scaler(self.scaler_pickle)
        self.encoder = import_encoder(self.encoder_pickle)
        
        # Check if all components are loaded
        if not self.model or not self.scaler or not self.encoder:
            print("⚠️ Warning: Not all ML components loaded successfully")
            
        print("IDS/IPS Server initialized successfully")
        
    def process_packet_data(self, raw_bytes):
        """
        Process raw packet bytes to make a prediction
        """
        try:
            # Format raw bytes into PyShark packets
            formatted_packets = format_raw([raw_bytes])
            
            # Extract features
            df = extract_packets(formatted_packets, self.features)
            if df.empty:
                return {"is_malicious": False, "reason": "No features extracted"}
            
            # Prepare data for model
            df = prepareData(df, self.scaler, self.encoder)
            if df.empty:
                return {"is_malicious": False, "reason": "No data after preparation"}
            
            # Make prediction
            predictions = prediction(self.model, df)
            
            # Format response
            # Assuming prediction returns 1 for attack, 0 for non-attack
            is_malicious = any(p == 1 for p in predictions)
            
            response = {
                "is_malicious": is_malicious,
                "reason": "Potential malicious traffic detected" if is_malicious else "Clean traffic"
            }
            
            return response
            
        except Exception as e:
            print(f"Error processing packet: {e}")
            return {"error": str(e)}
        
    def handle_client(self, client_socket):
        """
        Handle incoming client connection and process packet data
        """
        try:
            # Receive serialized packet data
            data = b''
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(chunk) < 4096:  # Assume end of message if chunk is smaller than buffer
                    break
            
            if not data:
                return
                
            # Deserialize the packet data
            packet_dict = pickle.loads(data)
            
            # Process the raw bytes
            if 'raw_bytes' in packet_dict:
                raw_bytes = packet_dict['raw_bytes']
                response = self.process_packet_data(raw_bytes)
                
                # Send response back to client
                client_socket.sendall(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
            
    def start(self):
        """
        Start the IDS/IPS server
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            print(f"[+] IDS/IPS Server listening on {self.host}:{self.port}")
            
            while True:
                client, addr = server.accept()
                print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
                
                # Handle client in a new thread
                client_handler = threading.Thread(target=self.handle_client, args=(client,))
                client_handler.daemon = True
                client_handler.start()
                
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            server.close()

def test_with_pcap():
    """
    Test the IDS/IPS with a pcap file
    """
    print("[*] Testing with pcap file...")
    pkt_buffer = pcap_to_raw('pcaps/test.pcap')
    packets = format_raw(pkt_buffer)
    
    df = extract_packets(packets, features)
    print("[+] Extracted features:")
    print(df)
    
    scaler = import_scaler(scaler_pickle)
    encoder = import_encoder(encoder_pickle)
    df = prepareData(df, scaler, encoder)
    print("[+] Prepared data:")
    print(df)
    
    model = import_model(model_pickle)
    results = prediction(model, df)
    print("[+] Prediction results:")
    print(results)
    
    # Count attacks vs non-attacks
    attack_count = sum(1 for r in results if r == 1)
    non_attack_count = sum(1 for r in results if r == 0)
    print(f"[+] Found {attack_count} attacks and {non_attack_count} non-attacks in the pcap file")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        test_with_pcap()
    else:
        # Start the IDS/IPS server
        ids_server = IDSServer(
            host=HOST,
            port=PORT,
            features=features,
            model_pickle=model_pickle,
            encoder_pickle=encoder_pickle,
            scaler_pickle=scaler_pickle
        )
        ids_server.start()