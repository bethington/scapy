import json
import struct
import threading
import time
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

class D2DualLocationMonitor:
    def __init__(self, client_json="client2gs.json", server_json="gs2client.json"):
        """Initialize the dual location monitor with packet definitions"""
        self.client_packet_definitions = self.load_packet_definitions(client_json)
        self.server_packet_definitions = self.load_packet_definitions(server_json)
        
        # Client-side position (movement commands sent TO server)
        self.client_x = 0
        self.client_y = 0
        self.client_stamina_running = False
        self.client_last_update = None
        self.client_packet_count = 0
        
        # Server-side position and stats (updates FROM server)
        self.server_x = 0
        self.server_y = 0
        self.server_hp = 0
        self.server_max_hp = 0
        self.server_mp = 0
        self.server_max_mp = 0
        self.server_stamina = 0
        self.server_max_stamina = 0
        self.server_hp_percent = 0
        self.server_last_update = None
        self.server_packet_count = 0
        
        # Packet IDs loaded from JSON
        self.client_movement_packets = {}
        self.client_stamina_packets = {}
        self.server_movement_packets = {}
        self.server_status_packets = {}
        self.load_packet_ids()
        
        # Movement history for both client and server
        self.client_history = []
        self.server_history = []
        self.max_history = 50
        
        # Display update thread
        self.running = False
        self.display_thread = None
        
        print("D2 Enhanced Player Monitor Initialized")
        print("Monitoring client commands and server updates...")
        print(f"Client movement packets: {list(self.client_movement_packets.keys())}")
        print(f"Client stamina packets: {list(self.client_stamina_packets.keys())}")
        print(f"Server movement packets: {list(self.server_movement_packets.keys())}")
        print(f"Server status packets: {list(self.server_status_packets.keys())}")
        print("-" * 60)
    
    def load_packet_definitions(self, json_file):
        """Load packet definitions from JSON file"""
        try:
            with open(json_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: {json_file} not found, using default packet definitions")
            return {}
    
    def load_packet_ids(self):
        """Load all relevant packet IDs from both JSON definitions"""
        # Client movement packets
        walk_packet = self.client_packet_definitions.get('D2GS_WALKTOLOCATION', {})
        run_packet = self.client_packet_definitions.get('D2GS_RUNTOLOCATION', {})
        
        if 'PacketId' in walk_packet:
            packet_id = int(walk_packet['PacketId'], 16)
            self.client_movement_packets[packet_id] = "D2GS_WALKTOLOCATION"
        else:
            self.client_movement_packets[0x01] = "D2GS_WALKTOLOCATION"  # Default
            
        if 'PacketId' in run_packet:
            packet_id = int(run_packet['PacketId'], 16)
            self.client_movement_packets[packet_id] = "D2GS_RUNTOLOCATION"
        else:
            self.client_movement_packets[0x03] = "D2GS_RUNTOLOCATION"  # Default
        
        # Client stamina packets
        stamina_on = self.client_packet_definitions.get('D2GS_STAMINA_ON', {})
        stamina_off = self.client_packet_definitions.get('D2GS_STAMINA_OFF', {})
        
        if 'PacketId' in stamina_on:
            packet_id = int(stamina_on['PacketId'], 16)
            self.client_stamina_packets[packet_id] = "D2GS_STAMINA_ON"
        else:
            self.client_stamina_packets[0x53] = "D2GS_STAMINA_ON"  # Default
            
        if 'PacketId' in stamina_off:
            packet_id = int(stamina_off['PacketId'], 16)
            self.client_stamina_packets[packet_id] = "D2GS_STAMINA_OFF"
        else:
            self.client_stamina_packets[0x54] = "D2GS_STAMINA_OFF"  # Default
        
        # Server movement and status packets
        stop_packet = self.server_packet_definitions.get('D2GS_PLAYERSTOP', {})
        move_packet = self.server_packet_definitions.get('D2GS_PLAYERMOVE', {})
        
        if 'PacketId' in stop_packet:
            packet_id = int(stop_packet['PacketId'], 16)
            self.server_movement_packets[packet_id] = "D2GS_PLAYERSTOP"
        else:
            self.server_movement_packets[0x0D] = "D2GS_PLAYERSTOP"  # Default
            
        if 'PacketId' in move_packet:
            packet_id = int(move_packet['PacketId'], 16)
            self.server_movement_packets[packet_id] = "D2GS_PLAYERMOVE"
        else:
            self.server_movement_packets[0x0F] = "D2GS_PLAYERMOVE"  # Default
        
        # Server HP/MP/Stamina update packets
        hpmp_update2 = self.server_packet_definitions.get('D2GS_HPMPUPDATE2', {})
        hpmp_update = self.server_packet_definitions.get('D2GS_HPMPUPDATE', {})
        walk_verify = self.server_packet_definitions.get('D2GS_WALKVERIFY', {})
        
        if 'PacketId' in hpmp_update2:
            packet_id = int(hpmp_update2['PacketId'], 16)
            self.server_status_packets[packet_id] = "D2GS_HPMPUPDATE2"
        else:
            self.server_status_packets[0x18] = "D2GS_HPMPUPDATE2"  # Default
            
        if 'PacketId' in hpmp_update:
            packet_id = int(hpmp_update['PacketId'], 16)
            self.server_status_packets[packet_id] = "D2GS_HPMPUPDATE"
        else:
            self.server_status_packets[0x95] = "D2GS_HPMPUPDATE"  # Default
            
        if 'PacketId' in walk_verify:
            packet_id = int(walk_verify['PacketId'], 16)
            self.server_status_packets[packet_id] = "D2GS_WALKVERIFY"
        else:
            self.server_status_packets[0x96] = "D2GS_WALKVERIFY"  # Default

    def parse_client_movement_packet(self, packet_data, packet_type):
        """Parse client movement packet and extract target coordinates"""
        try:
            if len(packet_data) < 5:  # Minimum size for movement packets
                return None, None
            
            # Parse the packet structure: [PacketId][nTargetX][nTargetY]
            packet_id = struct.unpack('B', packet_data[0:1])[0]
            target_x = struct.unpack('<H', packet_data[1:3])[0]  # Little endian short
            target_y = struct.unpack('<H', packet_data[3:5])[0]  # Little endian short
            
            return target_x, target_y
            
        except (struct.error, IndexError) as e:
            return None, None
    
    def parse_server_movement_packet(self, packet_data, packet_type):
        """Parse server movement packets - D2GS_PLAYERSTOP and D2GS_PLAYERMOVE"""
        try:
            if packet_type == "D2GS_PLAYERSTOP":
                # D2GS_PLAYERSTOP: [PacketId][nUnitType][nUnitGUID][bHitClass][nUnitX][nUnitY][nUnitHitClass][nUnitLife]
                if len(packet_data) >= 13:
                    packet_id = struct.unpack('B', packet_data[0:1])[0]
                    unit_type = struct.unpack('B', packet_data[1:2])[0]
                    unit_guid = struct.unpack('<I', packet_data[2:6])[0]
                    hit_class = struct.unpack('B', packet_data[6:7])[0]
                    pos_x = struct.unpack('<H', packet_data[7:9])[0]
                    pos_y = struct.unpack('<H', packet_data[9:11])[0]
                    unit_hit_class = struct.unpack('B', packet_data[11:12])[0]
                    unit_life = struct.unpack('B', packet_data[12:13])[0]
                    
                    # Store life percentage
                    self.server_hp_percent = unit_life
                    return pos_x, pos_y
                    
            elif packet_type == "D2GS_PLAYERMOVE":
                # D2GS_PLAYERMOVE: [PacketId][nUnitType][nUnitGUID][nMoveType][nTargetX][nTargetY][nUnitHitClass][nUnitX][nUnitY]
                if len(packet_data) >= 16:
                    packet_id = struct.unpack('B', packet_data[0:1])[0]
                    unit_type = struct.unpack('B', packet_data[1:2])[0]
                    unit_guid = struct.unpack('<I', packet_data[2:6])[0]
                    move_type = struct.unpack('B', packet_data[6:7])[0]
                    target_x = struct.unpack('<H', packet_data[7:9])[0]
                    target_y = struct.unpack('<H', packet_data[9:11])[0]
                    unit_hit_class = struct.unpack('B', packet_data[11:12])[0]
                    current_x = struct.unpack('<H', packet_data[12:14])[0]
                    current_y = struct.unpack('<H', packet_data[14:16])[0]
                    
                    return current_x, current_y
            
            return None, None
            
        except (struct.error, IndexError) as e:
            return None, None
    
    def parse_server_status_packet(self, packet_data, packet_type):
        """Parse server HP/MP/Stamina status packets"""
        try:
            if packet_type in ["D2GS_HPMPUPDATE2", "D2GS_HPMPUPDATE", "D2GS_WALKVERIFY"]:
                # These packets contain bitstream data that needs special parsing
                # For now, we'll extract what we can from the basic structure
                
                if packet_type == "D2GS_HPMPUPDATE2" and len(packet_data) >= 15:
                    # Contains HP, MP, Stamina, HPRegen, MPRegen, X, Y, dX, dY in bitstream
                    bitstream = packet_data[1:15]  # Skip packet ID
                    # This would need proper bitstream parsing - placeholder for now
                    return self.parse_bitstream_hpmp_full(bitstream)
                    
                elif packet_type == "D2GS_HPMPUPDATE" and len(packet_data) >= 13:
                    # Contains HP, MP, Stamina, X, Y, dX, dY in bitstream
                    bitstream = packet_data[1:13]  # Skip packet ID
                    return self.parse_bitstream_hpmp(bitstream)
                    
                elif packet_type == "D2GS_WALKVERIFY" and len(packet_data) >= 9:
                    # Contains Stamina, X, Y, dX, dY in bitstream
                    bitstream = packet_data[1:9]  # Skip packet ID
                    return self.parse_bitstream_stamina(bitstream)
            
            return None, None, None, None, None
            
        except (struct.error, IndexError) as e:
            return None, None, None, None, None
    
    def parse_bitstream_hpmp_full(self, bitstream):
        """Parse full HP/MP/Stamina bitstream (15-bit values)"""
        # Simplified parsing - would need proper bitstream implementation
        # This is a placeholder that tries to extract basic info
        try:
            if len(bitstream) >= 14:
                # Rough approximation - actual bitstream parsing is complex
                hp = struct.unpack('<H', bitstream[0:2])[0] & 0x7FFF  # 15 bits
                mp = struct.unpack('<H', bitstream[2:4])[0] & 0x7FFF  # 15 bits
                stamina = struct.unpack('<H', bitstream[4:6])[0] & 0x7FFF  # 15 bits
                x = struct.unpack('<H', bitstream[8:10])[0]  # 16 bits
                y = struct.unpack('<H', bitstream[10:12])[0]  # 16 bits
                return hp, mp, stamina, x, y
        except:
            pass
        return None, None, None, None, None
    
    def parse_bitstream_hpmp(self, bitstream):
        """Parse HP/MP/Stamina bitstream (15-bit values)"""
        # Simplified parsing - would need proper bitstream implementation
        try:
            if len(bitstream) >= 12:
                hp = struct.unpack('<H', bitstream[0:2])[0] & 0x7FFF
                mp = struct.unpack('<H', bitstream[2:4])[0] & 0x7FFF
                stamina = struct.unpack('<H', bitstream[4:6])[0] & 0x7FFF
                x = struct.unpack('<H', bitstream[6:8])[0]
                y = struct.unpack('<H', bitstream[8:10])[0]
                return hp, mp, stamina, x, y
        except:
            pass
        return None, None, None, None, None
    
    def parse_bitstream_stamina(self, bitstream):
        """Parse Stamina/Position bitstream"""
        try:
            if len(bitstream) >= 8:
                stamina = struct.unpack('<H', bitstream[0:2])[0] & 0x7FFF
                x = struct.unpack('<H', bitstream[2:4])[0]
                y = struct.unpack('<H', bitstream[4:6])[0]
                return None, None, stamina, x, y
        except:
            pass
        return None, None, None, None, None

    def update_client_location(self, x, y, packet_type):
        """Update client-side location (movement commands)"""
        self.client_x = x
        self.client_y = y
        self.client_last_update = datetime.now()
        self.client_packet_count += 1
        
        # Add to history
        movement = {
            'timestamp': self.client_last_update,
            'x': x,
            'y': y,
            'type': packet_type,
            'stamina_running': self.client_stamina_running
        }
        self.client_history.append(movement)
        if len(self.client_history) > self.max_history:
            self.client_history.pop(0)
        
        # Log the movement
        timestamp = self.client_last_update.strftime("%H:%M:%S.%f")[:-3]
        stamina_status = "🏃‍♂️" if self.client_stamina_running else "🚶‍♂️"
        print(f"[{timestamp}] CLIENT {packet_type}: Target ({x}, {y}) {stamina_status}")
    
    def update_client_stamina(self, running, packet_type):
        """Update client-side stamina status"""
        self.client_stamina_running = running
        self.client_last_update = datetime.now()
        self.client_packet_count += 1
        
        # Log the stamina change
        timestamp = self.client_last_update.strftime("%H:%M:%S.%f")[:-3]
        status = "🏃‍♂️ Running" if running else "🚶‍♂️ Walking"
        print(f"[{timestamp}] CLIENT {packet_type}: {status}")
    
    def update_server_location(self, x, y, packet_type):
        """Update server-side location (position updates)"""
        self.server_x = x
        self.server_y = y
        self.server_last_update = datetime.now()
        self.server_packet_count += 1
        
        # Add to history
        movement = {
            'timestamp': self.server_last_update,
            'x': x,
            'y': y,
            'type': packet_type,
            'hp_percent': self.server_hp_percent
        }
        self.server_history.append(movement)
        if len(self.server_history) > self.max_history:
            self.server_history.pop(0)
        
        # Log the movement
        timestamp = self.server_last_update.strftime("%H:%M:%S.%f")[:-3]
        health_info = f" (HP: {self.server_hp_percent}%)" if self.server_hp_percent > 0 else ""
        print(f"[{timestamp}] SERVER {packet_type}: Position ({x}, {y}){health_info}")
    
    def update_server_status(self, hp, mp, stamina, x, y, packet_type):
        """Update server-side status (HP/MP/Stamina updates)"""
        if hp is not None:
            self.server_hp = hp
        if mp is not None:
            self.server_mp = mp
        if stamina is not None:
            self.server_stamina = stamina
        if x is not None and y is not None:
            self.server_x = x
            self.server_y = y
        
        self.server_last_update = datetime.now()
        self.server_packet_count += 1
        
        # Add to history
        status_update = {
            'timestamp': self.server_last_update,
            'x': self.server_x,
            'y': self.server_y,
            'type': packet_type,
            'hp': hp,
            'mp': mp,
            'stamina': stamina
        }
        self.server_history.append(status_update)
        if len(self.server_history) > self.max_history:
            self.server_history.pop(0)
        
        # Log the status update
        timestamp = self.server_last_update.strftime("%H:%M:%S.%f")[:-3]
        status_parts = []
        if hp is not None:
            status_parts.append(f"HP: {hp}")
        if mp is not None:
            status_parts.append(f"MP: {mp}")
        if stamina is not None:
            status_parts.append(f"Stamina: {stamina}")
        if x is not None and y is not None:
            status_parts.append(f"Pos: ({x}, {y})")
        
        status_str = ", ".join(status_parts) if status_parts else "Status update"
        print(f"[{timestamp}] SERVER {packet_type}: {status_str}")
    
    def calculate_position_difference(self):
        """Calculate the difference between client and server positions"""
        if self.client_x == 0 and self.client_y == 0:
            return 0, 0, 0
        if self.server_x == 0 and self.server_y == 0:
            return 0, 0, 0
        
        diff_x = self.client_x - self.server_x
        diff_y = self.client_y - self.server_y
        distance = (diff_x**2 + diff_y**2)**0.5
        
        return diff_x, diff_y, round(distance, 2)
    
    def packet_handler(self, packet):
        """Handle captured packets and check for movement commands/updates"""
        try:
            # Check TCP packets
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                tcp_layer = packet[TCP]
                
                # Check D2 ports
                if tcp_layer.dport in [4000, 6112] or tcp_layer.sport in [4000, 6112]:
                    payload = packet[Raw].load
                    
                    if len(payload) >= 1:
                        packet_id = payload[0]
                        
                        # Check for client movement commands (TO server)
                        if packet_id in self.client_movement_packets:
                            packet_type = self.client_movement_packets[packet_id]
                            x, y = self.parse_client_movement_packet(payload, packet_type)
                            
                            if x is not None and y is not None:
                                self.update_client_location(x, y, packet_type)
                        
                        # Check for client stamina commands
                        elif packet_id in self.client_stamina_packets:
                            packet_type = self.client_stamina_packets[packet_id]
                            running = self.parse_client_stamina_packet(payload, packet_type)
                            
                            if running is not None:
                                self.update_client_stamina(running, packet_type)
                        
                        # Check for server movement updates (FROM server)
                        elif packet_id in self.server_movement_packets:
                            packet_type = self.server_movement_packets[packet_id]
                            x, y = self.parse_server_movement_packet(payload, packet_type)
                            
                            if x is not None and y is not None:
                                self.update_server_location(x, y, packet_type)
                        
                        # Check for server status updates (FROM server)
                        elif packet_id in self.server_status_packets:
                            packet_type = self.server_status_packets[packet_id]
                            hp, mp, stamina, x, y = self.parse_server_status_packet(payload, packet_type)
                            
                            if any(v is not None for v in [hp, mp, stamina, x, y]):
                                self.update_server_status(hp, mp, stamina, x, y, packet_type)
            
            # Check UDP packets
            elif packet.haslayer(UDP) and packet.haslayer(Raw):
                udp_layer = packet[UDP]
                
                if udp_layer.dport in [4000, 6112] or udp_layer.sport in [4000, 6112]:
                    payload = packet[Raw].load
                    
                    if len(payload) >= 1:
                        packet_id = payload[0]
                        
                        # Check for client movement commands
                        if packet_id in self.client_movement_packets:
                            packet_type = self.client_movement_packets[packet_id]
                            x, y = self.parse_client_movement_packet(payload, packet_type)
                            
                            if x is not None and y is not None:
                                self.update_client_location(x, y, packet_type)
                        
                        # Check for client stamina commands
                        elif packet_id in self.client_stamina_packets:
                            packet_type = self.client_stamina_packets[packet_id]
                            running = self.parse_client_stamina_packet(payload, packet_type)
                            
                            if running is not None:
                                self.update_client_stamina(running, packet_type)
                        
                        # Check for server movement updates
                        elif packet_id in self.server_movement_packets:
                            packet_type = self.server_movement_packets[packet_id]
                            x, y = self.parse_server_movement_packet(payload, packet_type)
                            
                            if x is not None and y is not None:
                                self.update_server_location(x, y, packet_type)
                        
                        # Check for server status updates
                        elif packet_id in self.server_status_packets:
                            packet_type = self.server_status_packets[packet_id]
                            hp, mp, stamina, x, y = self.parse_server_status_packet(payload, packet_type)
                            
                            if any(v is not None for v in [hp, mp, stamina, x, y]):
                                self.update_server_status(hp, mp, stamina, x, y, packet_type)
                                
        except Exception as e:
            # Silently ignore parsing errors
            pass
    
    def display_status(self):
        """Display current location and status for both client and server"""
        while self.running:
            try:
                # Clear screen and show current status
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                
                print("=" * 80)
                print("                D2 ENHANCED PLAYER MONITOR")
                print("=" * 80)
                print()
                
                # Client position and status
                print("CLIENT STATUS (Commands Sent to Server):")
                print(f"  Target Location:  X={self.client_x:>6}, Y={self.client_y:>6}")
                stamina_status = "🏃‍♂️ Running" if self.client_stamina_running else "🚶‍♂️ Walking"
                print(f"  Movement Mode:    {stamina_status}")
                print(f"  Commands Sent:    {self.client_packet_count}")
                if self.client_last_update:
                    time_diff = datetime.now() - self.client_last_update
                    print(f"  Last Command:     {self.client_last_update.strftime('%H:%M:%S')} ({time_diff.seconds}s ago)")
                else:
                    print("  Last Command:     No commands detected")
                
                print()
                
                # Server position and status
                print("SERVER STATUS (Updates from Server):")
                print(f"  Current Location: X={self.server_x:>6}, Y={self.server_y:>6}")
                if self.server_hp > 0 or self.server_mp > 0 or self.server_stamina > 0:
                    print(f"  Health (HP):      {self.server_hp:>6}")
                    print(f"  Mana (MP):        {self.server_mp:>6}")
                    print(f"  Stamina:          {self.server_stamina:>6}")
                if self.server_hp_percent > 0:
                    print(f"  Health Percent:   {self.server_hp_percent:>6}%")
                print(f"  Updates Received: {self.server_packet_count}")
                if self.server_last_update:
                    time_diff = datetime.now() - self.server_last_update
                    print(f"  Last Update:      {self.server_last_update.strftime('%H:%M:%S')} ({time_diff.seconds}s ago)")
                else:
                    print("  Last Update:      No updates detected")
                
                print()
                
                # Position difference analysis
                diff_x, diff_y, distance = self.calculate_position_difference()
                print("POSITION ANALYSIS:")
                print(f"  Difference:       ΔX={diff_x:>6}, ΔY={diff_y:>6}")
                print(f"  Distance Apart:   {distance:>6} units")
                
                if distance > 100:
                    print("  Status:           ⚠️  Large desync detected!")
                elif distance > 50:
                    print("  Status:           ⚠️  Moderate desync")
                elif distance > 0:
                    print("  Status:           ✅ Minor difference (normal)")
                else:
                    print("  Status:           ✅ Positions synchronized")
                
                print()
                print("Monitoring D2 traffic on ports 4000, 6112...")
                print("Tracking: Movement, Health, Mana, Stamina")
                print("Press Ctrl+C to stop monitoring")
                print()
                
                # Recent activity history
                print("RECENT ACTIVITY:")
                print("-" * 50)
                
                # Show last 5 activities from each side
                recent_client = self.client_history[-5:] if self.client_history else []
                recent_server = self.server_history[-5:] if self.server_history else []
                
                if recent_client:
                    print("Client Commands:")
                    for activity in recent_client:
                        time_str = activity['timestamp'].strftime("%H:%M:%S")
                        if 'stamina_running' in activity:
                            stamina = "🏃‍♂️" if activity.get('stamina_running') else "🚶‍♂️"
                            print(f"  {time_str} {activity['type']} → ({activity['x']}, {activity['y']}) {stamina}")
                        else:
                            print(f"  {time_str} {activity['type']}")
                
                if recent_server:
                    print("Server Updates:")
                    for activity in recent_server:
                        time_str = activity['timestamp'].strftime("%H:%M:%S")
                        info_parts = [f"({activity['x']}, {activity['y']})"]
                        
                        if activity.get('hp_percent', 0) > 0:
                            info_parts.append(f"HP: {activity['hp_percent']}%")
                        if activity.get('hp') is not None:
                            info_parts.append(f"HP: {activity['hp']}")
                        if activity.get('mp') is not None:
                            info_parts.append(f"MP: {activity['mp']}")
                        if activity.get('stamina') is not None:
                            info_parts.append(f"Stamina: {activity['stamina']}")
                        
                        info_str = " | ".join(info_parts)
                        print(f"  {time_str} {activity['type']} → {info_str}")
                
                time.sleep(1)  # Update every second
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Display error: {e}")
                time.sleep(1)
    
    def start_monitoring(self, interface=None, filter_str="tcp or udp"):
        """Start dual packet monitoring"""
        self.running = True
        
        # Start display thread
        self.display_thread = threading.Thread(target=self.display_status, daemon=True)
        self.display_thread.start()
        
        try:
            print(f"Starting enhanced packet capture on interface: {interface if interface else 'default'}")
            print(f"Filter: {filter_str}")
            print("Monitoring for D2 player packets (movement, health, mana, stamina)...")
            
            # Start packet capture
            if interface:
                sniff(iface=interface, prn=self.packet_handler, filter=filter_str, store=0)
            else:
                sniff(prn=self.packet_handler, filter=filter_str, store=0)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        except Exception as e:
            print(f"Monitoring error: {e}")
        finally:
            self.running = False
    
    def get_desync_statistics(self):
        """Calculate desynchronization statistics"""
        if not self.client_history or not self.server_history:
            return {}
        
        # Calculate average desync distance
        total_distance = 0
        comparisons = 0
        
        for client_move in self.client_history:
            # Find closest server update in time
            closest_server = None
            min_time_diff = float('inf')
            
            for server_move in self.server_history:
                time_diff = abs((client_move['timestamp'] - server_move['timestamp']).total_seconds())
                if time_diff < min_time_diff:
                    min_time_diff = time_diff
                    closest_server = server_move
            
            if closest_server and min_time_diff < 5:  # Within 5 seconds
                distance = ((client_move['x'] - closest_server['x'])**2 + 
                           (client_move['y'] - closest_server['y'])**2)**0.5
                total_distance += distance
                comparisons += 1
        
        avg_desync = total_distance / comparisons if comparisons > 0 else 0
        
        return {
            'average_desync': round(avg_desync, 2),
            'total_comparisons': comparisons,
            'client_movements': len(self.client_history),
            'server_updates': len(self.server_history)
        }

    def parse_client_stamina_packet(self, packet_data, packet_type):
        """Parse client stamina packets"""
        try:
            if packet_type == "D2GS_STAMINA_ON":
                return True
            elif packet_type == "D2GS_STAMINA_OFF":
                return False
        except Exception as e:
            pass
        return None

def main():
    """Main function with user interface"""
    print("D2 Enhanced Player Monitor")
    print("=" * 40)
    print("Tracks player location, health, mana, and stamina")
    print("Monitors both client commands and server updates")
    print()
    print("1. Start Enhanced Player Monitor")
    print("2. List Network Interfaces")
    print("3. Monitor Info & Packet Details")
    print("0. Exit")
    
    choice = input("\nSelect option: ").strip()
    
    if choice == "0":
        return
    elif choice == "1":
        monitor = D2DualLocationMonitor()
        interface = input("Enter network interface (or press Enter for default): ").strip()
        interface = interface if interface else None
        monitor.start_monitoring(interface)
    elif choice == "2":
        print("\nAvailable network interfaces:")
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")
    elif choice == "3":
        print("\nD2 Enhanced Player Monitor - Packet Information")
        print("=" * 50)
        print("\nClient-side packets monitored (commands TO server):")
        print("• D2GS_WALKTOLOCATION (0x01) - Walk movement commands")
        print("• D2GS_RUNTOLOCATION (0x03) - Run movement commands") 
        print("• D2GS_STAMINA_ON (0x53) - Start running mode")
        print("• D2GS_STAMINA_OFF (0x54) - Stop running mode")
        print("\nServer-side packets monitored (updates FROM server):")
        print("• D2GS_PLAYERSTOP (0x0D) - Player stopped with position and life%")
        print("• D2GS_PLAYERMOVE (0x0F) - Player movement with current position")
        print("• D2GS_HPMPUPDATE2 (0x18) - Full HP/MP/Stamina/Position update")
        print("• D2GS_HPMPUPDATE (0x95) - HP/MP/Stamina/Position update") 
        print("• D2GS_WALKVERIFY (0x96) - Stamina/Position verification")
        print("\nThis monitor provides comprehensive tracking of:")
        print("- Player position (client commands vs server position)")
        print("- Health, Mana, and Stamina values")
        print("- Movement mode (walking vs running)")
        print("- Desynchronization detection")
        input("\nPress Enter to return to main menu...")
        main()
    else:
        print("Invalid choice")
        main()

if __name__ == "__main__":
    main()