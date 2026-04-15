# SDN Project - Topology Change Detector

A simple OpenFlow controller that detects network topology changes.

## Requirements

- **Monitor switch/link events**: Track switch connections and disconnections
- **Update topology map**: Maintain current network topology
- **Display changes**: Log and show topology changes in real-time
- **Log updates**: Write topology changes to log file

## Structure

```
SDNProject/
├── controller.py      # OpenFlow controller with topology detection
├── topology.py      # Mininet topologies
└── README.md
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

## How It Works

1. **Controller** (`controller.py`):
   - Tracks switches via `EventOFPSwitchFeatures`
   - Monitors link changes via topology API
   - Logs all changes to `topology_changes.log`

2. **Topology** (`topology.py`):
   - Creates Mininet topology
   - Connects to remote controller at `127.0.0.1:6653`

## Port Configuration

- Default OpenFlow port: **6653**
- Controller listens on `127.0.0.1:6653`

## Testing

```bash
# In Mininet CLI
mininet> h1 ping h2
mininet> nodes
mininet> net

# To test link failure detection (triangle topo)
mininet> link s1 s2 down
mininet> pingall
mininet> link s1 s2 up
```
