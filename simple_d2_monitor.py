from scapy.all import *
import struct
import threading
import time
import json
import os
from datetime import datetime

class SimpleD2Monitor:
    def __init__(self):
        self.client_x = 0
        self.client_y = 0
        self.server_x = 0
        self.server_y = 0
        self.count = 0
        self.packet_ids = self.load_packet_definitions()
        
    def load_packet_definitions(self):
        """Load packet IDs from client2gs.json"""
        json_path = os.path.join(os.path.dirname(__file__), 'client2gs.json')
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
                return {
                    'WALKTOLOCATION': data.get('D2GS_WALKTOLOCATION', {}).get('id', 0x01),
                    'RUNTOLOCATION': data.get('D2GS_RUNTOLOCATION', {}).get('id', 0x03),
                    'PLAYERMOVE': data.get('D2GS_PLAYERMOVE', {}).get('id', 0x0f)
                }
        except FileNotFoundError:
            print("Warning: client2gs.json not found, using default packet IDs")
            return {'WALKTOLOCATION': 0x01, 'RUNTOLOCATION': 0x03, 'PLAYERMOVE': 0x0f}
        
    def monitor_packets(self):
        """Monitor D2 packets for client and server position updates"""
        def packet_handler(packet):
            if packet.haslayer(Raw):
                data = packet[Raw].load
                if len(data) >= 5:
                    packet_id = data[0]
                    
                    # Client-side movement (WALK/RUN TO LOCATION)
                    if packet_id in [self.packet_ids['WALKTOLOCATION'], self.packet_ids['RUNTOLOCATION']]:
                        try:
                            x = struct.unpack('<H', data[1:3])[0]
                            y = struct.unpack('<H', data[3:5])[0]
                            self.client_x, self.client_y = x, y
                            self.count += 1
                            action = "WALK" if packet_id == self.packet_ids['WALKTOLOCATION'] else "RUN"
                            self.display_positions(f"CLIENT {action}")
                        except:
                            pass
                    
                    # Server-side movement (PLAYER MOVE)
                    elif packet_id == self.packet_ids['PLAYERMOVE'] and len(data) >= 5:
                        try:
                            x = struct.unpack('<H', data[1:3])[0]
                            y = struct.unpack('<H', data[3:5])[0]
                            self.server_x, self.server_y = x, y
                            self.count += 1
                            self.display_positions("SERVER MOVE")
                        except:
                            pass
    
    def display_positions(self, action):
        """Display both client and server positions"""
        print(f"\r[{self.count:4d}] {action:12} | Client: ({self.client_x:5d}, {self.client_y:5d}) | Server: ({self.server_x:5d}, {self.server_y:5d})", 
              end="", flush=True)
        
        print("Monitoring D2 movement packets... Press Ctrl+C to stop")
        print("Format: [Count] ACTION | Client: (X, Y) | Server: (X, Y)")
        print(f"Packet IDs - Walk: 0x{self.packet_ids['WALKTOLOCATION']:02x}, Run: 0x{self.packet_ids['RUNTOLOCATION']:02x}, Move: 0x{self.packet_ids['PLAYERMOVE']:02x}")
        try:
            sniff(prn=packet_handler, filter="tcp or udp", store=0)
        except KeyboardInterrupt:
            print(f"\nMonitoring stopped.")
            print(f"Final Client position: ({self.client_x}, {self.client_y})")
            print(f"Final Server position: ({self.server_x}, {self.server_y})")

if __name__ == "__main__":
    monitor = SimpleD2Monitor()
    monitor.monitor_packets()