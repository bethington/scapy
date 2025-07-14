# Diablo 2 Packet Analysis Toolkit

A comprehensive Python toolkit for analyzing, monitoring, and crafting Diablo 2 network packets using Scapy. This project provides tools for real-time packet monitoring, packet injection, and detailed analysis of Diablo 2 game communication protocols.

## Features

- **Real-time Packet Monitoring**: Monitor and analyze live Diablo 2 network traffic
- **Dual Location Tracking**: Track both client-side and server-side player positions simultaneously
- **Packet Crafting**: Create and inject custom Diablo 2 packets
- **Multi-Protocol Support**: Support for Game Server (GS), Master Control Program (MCP), and Session Identification (SID) protocols
- **Movement Sequence Injection**: Automate character movement patterns
- **Skill Casting Simulation**: Inject skill casting packets for testing
- **JSON-Based Packet Definitions**: Easy-to-modify packet structure definitions

## Project Structure

```text
├── README.md                    # This file
├── d2_location_monitor.py       # Dual location monitoring (client + server)
├── d2_packet_crafter.py         # Packet creation and crafting utilities
├── d2_packet_injector.py        # Packet injection and automation
├── simple_d2_monitor.py         # Simple packet monitoring tool
├── client2gs.json              # Client-to-Game Server packet definitions
├── gs2client.json              # Game Server-to-Client packet definitions
├── client2mcps.json            # Client-to-MCP Server packet definitions
├── mcps2client.json            # MCP Server-to-Client packet definitions
├── client2sid.json             # Client-to-SID packet definitions
└── sid2client.json             # SID-to-Client packet definitions
```

## Requirements

- Python 3.7+
- Scapy library
- Windows OS (due to packet capture requirements)
- Administrator privileges (for packet injection)

## Installation

1. Clone or download this repository

2. Install required dependencies:

```bash
pip install scapy
```

1. Ensure you have administrator privileges for packet capture and injection

## Usage

### Basic Packet Monitoring

Monitor Diablo 2 packets in real-time:

```python
from simple_d2_monitor import SimpleD2Monitor

monitor = SimpleD2Monitor()
monitor.start_monitoring()
```

### Dual Location Monitoring

Track both client and server positions simultaneously:

```python
from d2_location_monitor import D2DualLocationMonitor

monitor = D2DualLocationMonitor()
monitor.start_monitoring("WiFi")  # Replace with your network interface
```

### Packet Crafting and Injection

Create and send custom packets:

```python
from d2_packet_crafter import D2PacketCrafter

crafter = D2PacketCrafter()

# Send a movement packet
crafter.send_packet("D2GS_WALKTOLOCATION", 
                   target_ip="127.0.0.1", 
                   target_port=4000,
                   nTargetX=100, 
                   nTargetY=200)

# List available packets
crafter.list_packets()
```

### Automated Movement Injection

Inject movement sequences:

```python
from d2_packet_injector import D2PacketInjector

injector = D2PacketInjector()

# Define movement coordinates
coordinates = [(100, 100), (150, 150), (200, 200)]

# Inject movement sequence
injector.inject_movement_sequence("127.0.0.1", 4000, coordinates)
```

### Skill Casting

Inject skill casting packets:

```python
# Cast skill on location
injector.inject_skill_cast("127.0.0.1", 4000, 
                          skill_type="left", 
                          x=150, y=150)

# Cast skill on entity
injector.inject_skill_cast("127.0.0.1", 4000, 
                          skill_type="right", 
                          unit_guid=12345)
```

## Packet Definitions

The toolkit uses JSON files to define packet structures for different Diablo 2 protocols:

### Game Server Protocol (client2gs.json / gs2client.json)

- Movement packets (WALKTOLOCATION, RUNTOLOCATION)
- Skill casting packets
- Player status updates
- Item interactions

### Master Control Program (client2mcps.json / mcps2client.json)

- Character selection
- Game creation/joining
- Account management

### Session Identification (client2sid.json / sid2client.json)

- Authentication
- Chat messages
- Friend list management

## Key Classes

### D2DualLocationMonitor

- Monitors both client and server position data
- Tracks player statistics (HP, MP, Stamina)
- Maintains movement history
- Real-time display updates

### D2PacketCrafter

- Creates packets from JSON definitions
- Supports multiple data types (BYTE, WORD, DWORD, strings)
- TCP and UDP packet creation
- Flexible parameter handling

### D2PacketInjector

- Automated packet injection
- Movement sequence automation
- Skill casting simulation
- Network monitoring capabilities

### SimpleD2Monitor

- Lightweight packet monitoring
- Basic position tracking
- Easy-to-use interface

## Network Interface Configuration

To monitor packets, you'll need to specify your network interface. Common interfaces:

- `"WiFi"` - Wireless connection
- `"Ethernet"` - Wired connection
- `"Local Area Connection"` - Windows local connection

Use `ipconfig` in Command Prompt to identify your active network interface.

## Security and Legal Considerations

⚠️ **Important Notice**: This toolkit is designed for educational purposes, network analysis, and authorized testing environments only.

- Only use on networks and systems you own or have explicit permission to test
- Packet injection may be considered a form of network manipulation
- Some game servers may detect and ban accounts using packet injection
- Always comply with game Terms of Service and local laws
- Use responsibly and ethically

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run Python as Administrator for packet capture
2. **Interface Not Found**: Check network interface names using `ipconfig`
3. **Packets Not Captured**: Ensure Diablo 2 is running and generating network traffic
4. **JSON Parse Errors**: Verify JSON file integrity and syntax

### Debug Mode

Enable verbose output in Scapy for detailed packet information:

```python
conf.verb = 2  # Set Scapy verbosity level
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request

## License

This project is provided for educational and research purposes. Please respect game Terms of Service and applicable laws when using this toolkit.

## Disclaimer

This toolkit is not affiliated with Blizzard Entertainment or Diablo 2. Use at your own risk and responsibility.
