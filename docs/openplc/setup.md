# OpenPLC Setup Documentation
## Installation Details
**Server:** openplc-server
**IP Addresses:**
- Management: 192.168.56.20
- Production: 192.168.100.20
**OpenPLC Version:** 3.x
**Installation Date:** 2024-12-28
## Access
**Web Interface:**
- URL: http://192.168.56.20:8080
- Username: openplc
- Password: [stored in password manager]
**Modbus TCP:**
- IP: 192.168.100.20
- Port: 502
- Device ID: 1
## Firewall Rules
```bash
# Web interface (management network only)
sudo ufw allow from 192.168.56.0/24 to any port 8080
# Modbus TCP (production network only)
sudo ufw allow from 192.168.100.0/24 to any port 502
```
## Programs
### first_program.st
- Type: Simple I/O mapping
- Input: %QX0.1 (Discrete Input 0) * now Iputs can be set by modbus
- Output: %QX0.0 (Coil 0)
- Logic: Direct copy (Output = Input)
- Status: Running
## Testing**Modbus test from ubuntu-test-02:**
```bash
ssh otadmin@192.168.56.21
python3 ~/modbus_test.py
```
## Troubleshooting
**PLC not accessible:**
```bash
# Check service
sudo systemctl status openplc
# Restart if needed
sudo systemctl restart openplc
# Check firewall
sudo ufw status
```
**Modbus connection fails:**
```bash
# Check port
sudo netstat -tlnp | grep 502
# Check from client
nc -zv 192.168.100.20 502
```
## Next Steps
- H10: Install ScadaBR for HMI
- H12: Connect ScadaBR to OpenPLC via Modbus
- H16: Analyze Modbus traffic with Wireshark
