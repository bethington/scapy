from scapy.all import *
import time
import threading
import math
import random
from d2_packet_crafter import D2PacketCrafter

class D2PacketInjector:
    def __init__(self):
        self.crafter = D2PacketCrafter()
        self.running = False
        self.injection_thread = None
    
    def inject_movement_sequence(self, target_ip, target_port, coordinates):
        """Inject a sequence of movement packets"""
        try:
            for x, y in coordinates:
                packet = self.crafter.send_packet("D2GS_WALKTOLOCATION",
                                                target_ip=target_ip,
                                                target_port=target_port,
                                                nTargetX=x,
                                                nTargetY=y)
                time.sleep(0.1)  # Small delay between packets
            return True
        except Exception as e:
            print(f"Error in movement sequence: {e}")
            return False
    
    def inject_skill_cast(self, target_ip, target_port, skill_type="left", x=None, y=None, unit_guid=None):
        """Inject skill casting packets"""
        try:
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
            else:
                print("Error: Must specify either location (x, y) or unit_guid")
                return False
            return True
        except Exception as e:
            print(f"Error casting skill: {e}")
            return False
    
    def start_packet_monitoring(self, interface="WiFi"):
        """Start monitoring packets"""
        def packet_handler(packet):
            try:
                if packet.haslayer(TCP) and packet[TCP].dport in [4000, 6112]:
                    print(f"D2 Packet detected: {packet.summary()}")
                    if packet.haslayer(Raw):
                        print(f"Payload: {packet[Raw].load.hex()}")
            except Exception as e:
                print(f"Error processing packet: {e}")
        
        try:
            print(f"Starting packet monitoring on interface: {interface}")
            sniff(iface=interface, prn=packet_handler, filter="tcp", store=0)
        except Exception as e:
            print(f"Error starting packet monitoring: {e}")
            print("Available interfaces: ", get_if_list())
    
    def stop_monitoring(self):
        """Stop packet monitoring if running"""
        self.running = False
        if self.injection_thread and self.injection_thread.is_alive():
            self.injection_thread.join(timeout=1)
    
    def start_monitoring_threaded(self, interface="WiFi"):
        """Start packet monitoring in a separate thread"""
        if self.running:
            print("Monitoring already running")
            return False
            
        self.running = True
        self.injection_thread = threading.Thread(
            target=self.start_packet_monitoring, 
            args=(interface,)
        )
        self.injection_thread.daemon = True
        self.injection_thread.start()
        return True
    
    def automated_bot_sequence(self, target_ip, target_port):
        """Example automated sequence"""
        try:
            print("Starting automated bot sequence...")
            
            # Ping sequence
            self.crafter.send_packet("D2GS_PING",
                                   target_ip=target_ip,
                                   target_port=target_port,
                                   nTickCount=int(time.time() * 1000),
                                   nDelay=0,
                                   nWardenOrZero=0)
            
            time.sleep(1)
            
            # Movement pattern
            coordinates = [(100, 100), (200, 150), (300, 200), (400, 250)]
            success = self.inject_movement_sequence(target_ip, target_port, coordinates)
            
            if success:
                time.sleep(1)
                
                # Use a potion
                self.crafter.send_packet("D2GS_USEBELTITEM",
                                       target_ip=target_ip,
                                       target_port=target_port,
                                       nItemGUID=123456,
                                       bOnMerc=0,
                                       Unused=0)
                print("Automated sequence completed successfully")
                return True
            else:
                print("Movement sequence failed")
                return False
                
        except Exception as e:
            print(f"Error in automated sequence: {e}")
            return False
    
    def inject_continuous_movement(self, target_ip, target_port, pattern="circle", duration=10):
        """Inject continuous movement in a pattern"""
        try:
            start_time = time.time()
            center_x, center_y = 500, 500
            radius = 100
            angle = 0
            
            print(f"Starting continuous {pattern} movement for {duration} seconds...")
            
            while time.time() - start_time < duration:
                if pattern == "circle":
                    x = int(center_x + radius * math.cos(angle))
                    y = int(center_y + radius * math.sin(angle))
                    angle += 0.1
                elif pattern == "square":
                    # Simple square pattern
                    step = int((time.time() - start_time) * 10) % 400
                    if step < 100:
                        x, y = center_x + step, center_y
                    elif step < 200:
                        x, y = center_x + 100, center_y + (step - 100)
                    elif step < 300:
                        x, y = center_x + 100 - (step - 200), center_y + 100
                    else:
                        x, y = center_x, center_y + 100 - (step - 300)
                else:
                    # Random movement
                    x = center_x + random.randint(-radius, radius)
                    y = center_y + random.randint(-radius, radius)
                
                self.crafter.send_packet("D2GS_WALKTOLOCATION",
                                       target_ip=target_ip,
                                       target_port=target_port,
                                       nTargetX=x,
                                       nTargetY=y)
                time.sleep(0.2)
            
            print("Continuous movement completed")
            return True
            
        except Exception as e:
            print(f"Error in continuous movement: {e}")
            return False

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
        print("6. Continuous movement patterns")
        print("7. Skill casting test")
        print("8. Stop monitoring")
        print("0. Exit")
        
        try:
            choice = input("Select option: ").strip()
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        
        if choice == "0":
            break
        elif choice == "1":
            injector.crafter.list_packets()
        elif choice == "2":
            try:
                packet_name = input("Enter packet name: ").strip()
                if not packet_name:
                    print("Invalid packet name")
                    continue
                    
                target_ip = input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
                target_port = int(input("Target port (default 4000): ").strip() or "4000")
                
                injector.crafter.show_packet_structure(packet_name)
                # Here you would collect field values from user input
                injector.crafter.send_packet(packet_name, target_ip=target_ip, target_port=target_port)
            except ValueError:
                print("Invalid port number")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "3":
            try:
                target_ip = input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
                target_port = int(input("Target port (default 4000): ").strip() or "4000")
                coordinates = [(100, 100), (200, 200), (300, 300)]
                success = injector.inject_movement_sequence(target_ip, target_port, coordinates)
                if success:
                    print("Movement sequence completed successfully")
                else:
                    print("Movement sequence failed")
            except ValueError:
                print("Invalid port number")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "4":
            interface = input("Network interface (default WiFi): ").strip() or "WiFi"
            injector.start_monitoring_threaded(interface)
        elif choice == "5":
            try:
                target_ip = input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
                target_port = int(input("Target port (default 4000): ").strip() or "4000")
                success = injector.automated_bot_sequence(target_ip, target_port)
                if success:
                    print("Automated sequence completed successfully")
                else:
                    print("Automated sequence failed")
            except ValueError:
                print("Invalid port number")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "6":
            try:
                target_ip = input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
                target_port = int(input("Target port (default 4000): ").strip() or "4000")
                pattern = input("Pattern (circle/square/random, default circle): ").strip() or "circle"
                duration = int(input("Duration in seconds (default 10): ").strip() or "10")
                success = injector.inject_continuous_movement(target_ip, target_port, pattern, duration)
                if success:
                    print("Continuous movement completed successfully")
                else:
                    print("Continuous movement failed")
            except ValueError:
                print("Invalid input")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "7":
            try:
                target_ip = input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
                target_port = int(input("Target port (default 4000): ").strip() or "4000")
                skill_type = input("Skill type (left/right, default left): ").strip() or "left"
                x = int(input("Target X coordinate (default 150): ").strip() or "150")
                y = int(input("Target Y coordinate (default 150): ").strip() or "150")
                success = injector.inject_skill_cast(target_ip, target_port, skill_type, x, y)
                if success:
                    print("Skill cast completed successfully")
                else:
                    print("Skill cast failed")
            except ValueError:
                print("Invalid input")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "8":
            injector.stop_monitoring()
            print("Monitoring stopped")
        else:
            print("Invalid choice. Please try again.")
    
    # Cleanup
    injector.stop_monitoring()

if __name__ == "__main__":
    interactive_injector()