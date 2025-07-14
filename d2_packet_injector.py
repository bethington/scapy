from scapy.all import *
import time
import threading
from d2_packet_crafter import D2PacketCrafter

class D2PacketInjector:
    def __init__(self):
        self.crafter = D2PacketCrafter()
        self.running = False
        self.injection_thread = None
    
    def inject_movement_sequence(self, target_ip, target_port, coordinates):
        """Inject a sequence of movement packets"""
        for x, y in coordinates:
            packet = self.crafter.send_packet("D2GS_WALKTOLOCATION",
                                            target_ip=target_ip,
                                            target_port=target_port,
                                            nTargetX=x,
                                            nTargetY=y)
            time.sleep(0.1)  # Small delay between packets
    
    def inject_skill_cast(self, target_ip, target_port, skill_type="left", x=None, y=None, unit_guid=None):
        """Inject skill casting packets"""
        if x is not None and y is not None:
            # Cast on location
            packet_name = "D2GS_LEFTSKILLONLOCATION" if skill_type == "left" else "D2GS_RIGHTSKILLONLOCATION"
            self.crafter.send_packet(packet_name,
                                   target_ip=target_ip,
                                   target_port=target_port,
                                   nTargetX=x,
                                   nTargetY=y)
        elif unit_guid is not None:
            # Cast on entity
            packet_name = "D2GS_LEFTSKILLONENTITY" if skill_type == "left" else "D2GS_RIGHTSKILLONENTITY"
            self.crafter.send_packet(packet_name,
                                   target_ip=target_ip,
                                   target_port=target_port,
                                   nUnitType=1,  # Monster type
                                   nUnitGUID=unit_guid)
    
    def start_packet_monitoring(self, interface="WiFi"):
        """Start monitoring packets"""
        def packet_handler(packet):
            if packet.haslayer(TCP) and packet[TCP].dport in [4000, 6112]:
                print(f"D2 Packet detected: {packet.summary()}")
                if packet.haslayer(Raw):
                    print(f"Payload: {packet[Raw].load.hex()}")
        
        print(f"Starting packet monitoring on interface: {interface}")
        sniff(iface=interface, prn=packet_handler, filter="tcp", store=0)
    
    def automated_bot_sequence(self, target_ip, target_port):
        """Example automated sequence"""
        print("Starting automated bot sequence...")
        
        # Login sequence
        self.crafter.send_packet("D2GS_PING",
                               target_ip=target_ip,
                               target_port=target_port,
                               nTickCount=int(time.time() * 1000),
                               nDelay=0,
                               nWardenOrZero=0)
        
        time.sleep(1)
        
        # Movement pattern
        coordinates = [(100, 100), (200, 150), (300, 200), (400, 250)]
        self.inject_movement_sequence(target_ip, target_port, coordinates)
        
        # Use a potion
        self.crafter.send_packet("D2GS_USEBELTITEM",
                               target_ip=target_ip,
                               target_port=target_port,
                               nItemGUID=123456,
                               bOnMerc=0,
                               Unused=0)

def interactive_injector():
    """Interactive packet injection interface"""
    injector = D2PacketInjector()
    
    while True:
        print("\n=== D2 Packet Injector ===")
        print("1. List available packets")
        print("2. Craft and send custom packet")
        print("3. Send movement sequence")
        print("4. Start packet monitoring")
        print("5. Run automated sequence")
        print("0. Exit")
        
        choice = input("Select option: ")
        
        if choice == "0":
            break
        elif choice == "1":
            injector.crafter.list_packets()
        elif choice == "2":
            packet_name = input("Enter packet name: ")
            target_ip = input("Target IP (default 127.0.0.1): ") or "127.0.0.1"
            target_port = int(input("Target port (default 4000): ") or "4000")
            
            try:
                injector.crafter.show_packet_structure(packet_name)
                # Here you would collect field values from user input
                injector.crafter.send_packet(packet_name, target_ip, target_port)
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "3":
            target_ip = input("Target IP (default 127.0.0.1): ") or "127.0.0.1"
            target_port = int(input("Target port (default 4000): ") or "4000")
            coordinates = [(100, 100), (200, 200), (300, 300)]
            injector.inject_movement_sequence(target_ip, target_port, coordinates)
        elif choice == "4":
            interface = input("Network interface (default WiFi): ") or "WiFi"
            injector.start_packet_monitoring(interface)
        elif choice == "5":
            target_ip = input("Target IP (default 127.0.0.1): ") or "127.0.0.1"
            target_port = int(input("Target port (default 4000): ") or "4000")
            injector.automated_bot_sequence(target_ip, target_port)

if __name__ == "__main__":
    interactive_injector()