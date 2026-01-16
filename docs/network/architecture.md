# OT Lab Network Architecture
## Network Zones
### Management Network (192.168.56.0/24)
- **Purpose:** Administrative access, monitoring, management
- **Access:** From host machine
- **Protocols:** SSH (22), HTTP/HTTPS (80/443), SNMP
- **Security:** Firewall rules, key-based SSH
- **VMs:**
- openplc-server: 192.168.56.20
- ubuntu-test-02: 192.168.56.21
- Future: ScadaBR: 192.168.56.30
### Production Network (192.168.100.0/24)
- **Purpose:** OT protocols, PLC communication
- **Access:** NO internet, isolated
- **Protocols:** Modbus TCP (502), OPC-UA (4840)
- **Security:** Network isolation, firewall
- **VMs:**
- openplc-server: 192.168.100.20
- ubuntu-test-02: 192.168.100.21
### Internet Network (10.0.2.0/24 - NAT)
- **Purpose:** Updates, package downloads
- **Access:** Management VMs only
- **Security:** Not available to production PLCs
## Security Rules
### Firewall Policy (UFW)
