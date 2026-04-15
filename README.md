# SDN Project - Topology Viewer and Network Controller

An OpenFlow 1.3 controller that implements a self-healing network with topology change detection and L2 switching capabilities.

## Features

- **L2 Switching**: MAC address learning with flow-based forwarding
- **Topology Change Detection**: Monitors switch/link join and leave events using OS Ken's topology API
- **Self-Healing**: Automatically flushes flow tables when topology changes to force re-learning
- **ARP Storm Mitigation**: Prevents broadcast storms from ARP requests
- **Real-time Visualization**: Generates network topology graph using NetworkX/Matplotlib

## Architecture

```
SDNProject/
├── controller.py      # OpenFlow controller with topology detection & L2 switching
├── topology.py      # Mininet topology definitions
├── README.md        # This file
└── network_topology.png   # Generated topology visualization
```

## Quick Start

### Terminal 1: Start Controller
```bash
sudo PYTHONPATH=. osken-manager --observe-links controller.py
```

### Terminal 2: Start Mininet
```bash
sudo mn --switch ovs --controller remote --custom topology.py --topo single
```

Available topologies:
- `single` - 1 switch, 2 hosts
- `triangle` - 3 switches, 2 hosts (for link failure testing)
- `hierarchical` - 3 switches, 4 hosts in tree layout

## How It Works

### 1. L2 Switching Logic
The controller learns MAC addresses from incoming packets and installs flow rules for efficient forwarding:

- Unknown destinations → Flood
- Known destinations → Install flow and forward to specific port

### 2. Topology Change Detection
The controller listens for OS Ken topology events:
- `EventSwitchEnter` / `EventSwitchLeave` - Switch connections
- `EventLinkAdd` / `EventLinkDelete` - Link changes
- `EventHostAdd` - New host detection

### 3. Self-Healing Mechanism
When topology changes detected:
1. Clear MAC address tables
2. Clear ARP history
3. Delete all flow rules from switches
4. Re-install table-miss rules

This forces the network to re-learn paths, preventing forwarding loops and blackholes.

### 4. ARP Storm Mitigation
Tracks ARP requests using signature `(switch_id, src_mac, src_ip, dst_ip)`. Drops duplicates within 5 seconds.

### 5. Visualization
The controller uses NetworkX to build a graph representation of the network and renders it to `network_topology.png` on each topology change.

## Port Configuration

- **OpenFlow Port**: 6653
- **Controller Listen Address**: 127.0.0.1:6653

## Testing

```bash
# In Mininet CLI
mininet> h1 ping h2
mininet> nodes
mininet> net

# Test link failure detection (triangle topo)
mininet> link s1 s2 down
mininet> pingall
mininet> link s1 s2 up
```
