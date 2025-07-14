import json
import struct
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import socket

class D2PacketCrafter:
    def __init__(self, json_file="client2gs.json"):
        """Initialize the packet crafter with JSON definitions"""
        with open(json_file, 'r') as f:
            self.packet_definitions = json.load(f)
        
        # Type mappings for struct packing
        self.type_mapping = {
            'BYTE': 'B',
            'char': 'c',
            'short': 'H',
            'WORD': 'H',
            'int': 'I',
            'DWORD': 'I',
            'std::string': 's'
        }
    
    def craft_packet(self, packet_name, **kwargs):
        """Craft a packet based on its definition"""
        if packet_name not in self.packet_definitions:
            raise ValueError(f"Packet {packet_name} not found in definitions")
        
        packet_def = self.packet_definitions[packet_name]
        packet_data = bytearray()
        
        print(f"Crafting packet: {packet_name}")
        print(f"Packet ID: {packet_def['PacketId']}")
        
        for field in packet_def['Structure']:
            field_type = list(field.keys())[0]
            field_name = list(field.values())[0]
            
            if field_name == "PacketId":
                # Convert hex string to int
                packet_id = int(packet_def['PacketId'], 16)
                packet_data.extend(struct.pack('B', packet_id))
                print(f"  {field_name}: 0x{packet_id:02X}")
            
            elif field_type in ['BYTE', 'char']:
                value = kwargs.get(field_name, 0)
                packet_data.extend(struct.pack('B', value))
                print(f"  {field_name}: {value}")
            
            elif field_type in ['short', 'WORD']:
                value = kwargs.get(field_name, 0)
                packet_data.extend(struct.pack('<H', value))  # Little endian
                print(f"  {field_name}: {value}")
            
            elif field_type in ['int', 'DWORD']:
                value = kwargs.get(field_name, 0)
                packet_data.extend(struct.pack('<I', value))  # Little endian
                print(f"  {field_name}: {value}")
            
            elif field_type == 'std::string':
                value = kwargs.get(field_name, "")
                if isinstance(value, str):
                    value = value.encode('utf-8')
                packet_data.extend(value)
                packet_data.extend(b'\x00')  # Null terminator
                print(f"  {field_name}: {value.decode('utf-8') if isinstance(value, bytes) else value}")
        
        return bytes(packet_data)
    
    def create_scapy_packet(self, packet_name, target_ip="127.0.0.1", target_port=4000, **kwargs):
        """Create a complete Scapy packet with IP/TCP headers"""
        payload = self.craft_packet(packet_name, **kwargs)
        
        # Create the complete packet
        packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=payload)
        return packet
    
    def send_packet(self, packet_name, target_ip="127.0.0.1", target_port=4000, **kwargs):
        """Send a crafted packet"""
        packet = self.create_scapy_packet(packet_name, target_ip, target_port, **kwargs)
        
        print(f"\nSending packet to {target_ip}:{target_port}")
        print(f"Packet summary: {packet.summary()}")
        
        # Send the packet
        send(packet, verbose=True)
        return packet
    
    def send_udp_packet(self, packet_name, target_ip="127.0.0.1", target_port=4000, **kwargs):
        """Send a crafted UDP packet"""
        payload = self.craft_packet(packet_name, **kwargs)
        packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload)
        
        print(f"\nSending UDP packet to {target_ip}:{target_port}")
        print(f"Packet summary: {packet.summary()}")
        
        send(packet, verbose=True)
        return packet
    
    def list_packets(self):
        """List all available packet types"""
        print("Available packet types:")
        for name, definition in self.packet_definitions.items():
            print(f"  {name} (ID: {definition['PacketId']}) - Size: {definition['Size']}")
            if definition.get('Description'):
                print(f"    Description: {definition['Description']}")
    
    def show_packet_structure(self, packet_name):
        """Show the structure of a specific packet"""
        if packet_name not in self.packet_definitions:
            print(f"Packet {packet_name} not found")
            return
        
        packet_def = self.packet_definitions[packet_name]
        print(f"\nPacket: {packet_name}")
        print(f"ID: {packet_def['PacketId']}")
        print(f"Size: {packet_def['Size']}")
        print(f"Description: {packet_def.get('Description', 'N/A')}")
        print("Structure:")
        
        for field in packet_def['Structure']:
            field_type = list(field.keys())[0]
            field_name = list(field.values())[0]
            print(f"  {field_type} {field_name}")

def main():
    """Example usage of the packet crafter"""
    crafter = D2PacketCrafter()
    
    # List all available packets
    crafter.list_packets()
    
    # Show structure of a specific packet
    print("\n" + "="*50)
    crafter.show_packet_structure("D2GS_WALKTOLOCATION")
    
    # Example: Craft a walk to location packet
    print("\n" + "="*50)
    walk_packet = crafter.craft_packet("D2GS_WALKTOLOCATION", 
                                     nTargetX=1000, 
                                     nTargetY=2000)
    print(f"Raw packet data: {walk_packet.hex()}")
    
    # Example: Craft a chat packet
    print("\n" + "="*50)
    chat_packet = crafter.craft_packet("D2GS_CHAT",
                                     nType=1,
                                     nLanguageCode=0,
                                     szMessage="Hello World!",
                                     szTarget="",
                                     szUnknown="")
    print(f"Raw packet data: {chat_packet.hex()}")
    
    # Example: Send a packet (uncomment to actually send)
    # packet = crafter.send_packet("D2GS_WALKTOLOCATION", 
    #                             target_ip="127.0.0.1", 
    #                             target_port=4000,
    #                             nTargetX=1000, 
    #                             nTargetY=2000)

if __name__ == "__main__":
    main()