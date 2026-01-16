import socket
import struct
import time
from scapy.all import ARP, Ether, srp, sniff, IP, TCP
from datetime import datetime
import ipaddress

# Snap7 voor Siemens PLC communicatie
try:
    import snap7
    from snap7.util import get_bool, get_int, get_real, get_string
    SNAP7_AVAILABLE = True
except ImportError:
    SNAP7_AVAILABLE = False
    print("⚠ snap7 niet geïnstalleerd - Siemens PLC scanning beperkt")

class NetworkScanner:
    """Scanner voor OT/ICS netwerk devices"""
    
    def __init__(self):
        self.discovered_devices = []
        self.protocols = {
            102: 'S7Comm (Siemens)',
            502: 'Modbus',
            2222: 'EtherNet/IP',
            44818: 'EtherNet/IP',
            20000: 'DNP3',
            4840: 'OPC UA',
            1911: 'Niagara Fox',
            5007: 'Siemens WinCC',
            34962: 'Profinet DCP',
            34964: 'Profinet'
        }
    
    def active_scan(self, network_range, timeout=2):
        """
        Actieve netwerk scan - stuurt pakketten naar devices
        Detecteert IP's, open poorten en OT protocollen
        """
        print("\n" + "=" * 70)
        print(" " * 20 + "🔍 ACTIEVE NETWERK SCAN")
        print("=" * 70)
        print(f"\nNetwerk range: {network_range}")
        print(f"Timeout: {timeout}s per host")
        print("\nScanning... dit kan enkele minuten duren...\n")
        
        discovered = []
        
        # Parse network range
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
        except ValueError as e:
            print(f"❌ Ongeldige network range: {e}")
            return []
        
        total_hosts = network.num_addresses
        scanned = 0
        
        for ip in network.hosts():
            ip_str = str(ip)
            scanned += 1
            
            # Progress indicator
            if scanned % 10 == 0:
                print(f"  Gescand: {scanned}/{total_hosts} hosts...", end='\r')
            
            # Check of host online is via ping/ARP
            if self._is_host_alive(ip_str, timeout=1):
                print(f"\n✓ Host gevonden: {ip_str}")
                
                device_info = {
                    'ip': ip_str,
                    'mac': self._get_mac_address(ip_str),
                    'hostname': self._get_hostname(ip_str),
                    'open_ports': [],
                    'protocols': [],
                    'device_type': 'Unknown',
                    'vendor': 'Unknown',
                    'scan_type': 'active'
                }
                
                # Scan OT/ICS poorten
                open_ports = self._scan_ot_ports(ip_str, timeout)
                device_info['open_ports'] = open_ports
                
                # Identificeer protocollen en device type
                for port in open_ports:
                    if port in self.protocols:
                        protocol = self.protocols[port]
                        device_info['protocols'].append(protocol)
                        print(f"  → Protocol: {protocol} (poort {port})")
                        
                        # Probeer device details op te halen
                        if port == 102:  # S7Comm
                            plc_info = self._scan_siemens_plc(ip_str)
                            if plc_info:
                                device_info.update(plc_info)
                
                # Bepaal device type op basis van open poorten
                device_info['device_type'] = self._identify_device_type(open_ports)
                
                discovered.append(device_info)
                print(f"  Type: {device_info['device_type']}")
        
        print(f"\n\n✓ Scan compleet! {len(discovered)} OT devices gevonden.\n")
        self.discovered_devices = discovered
        return discovered
    
    def passive_scan(self, interface=None, duration=60, filter_ot=True):
        """
        Passieve netwerk scan - luistert naar netwerkverkeer
        Detecteert OT protocollen zonder actieve pakketten te sturen
        """
        print("\n" + "=" * 70)
        print(" " * 20 + "👂 PASSIEVE NETWERK SCAN")
        print("=" * 70)
        print(f"\nDuur: {duration} seconden")
        print("Luisteren naar OT/ICS verkeer...")
        print("\n⚠ Deze scan vereist root/admin rechten!")
        print("Druk Ctrl+C om te stoppen\n")
        
        discovered = {}
        start_time = time.time()
        packet_count = 0
        
        def packet_handler(packet):
            nonlocal packet_count
            packet_count += 1
            
            # Progress indicator
            elapsed = int(time.time() - start_time)
            if packet_count % 100 == 0:
                print(f"  Pakketten: {packet_count} | Tijd: {elapsed}/{duration}s | Devices: {len(discovered)}", end='\r')
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Filter lokale IP's
                if not self._is_local_ip(src_ip):
                    return
                
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    
                    # Check voor OT protocollen
                    for port in [sport, dport]:
                        if port in self.protocols:
                            ip = src_ip if port == sport else dst_ip
                            
                            if ip not in discovered:
                                discovered[ip] = {
                                    'ip': ip,
                                    'protocols': set(),
                                    'ports': set(),
                                    'first_seen': datetime.now(),
                                    'packet_count': 0,
                                    'scan_type': 'passive'
                                }
                            
                            discovered[ip]['protocols'].add(self.protocols[port])
                            discovered[ip]['ports'].add(port)
                            discovered[ip]['packet_count'] += 1
                            discovered[ip]['last_seen'] = datetime.now()
        
        try:
            # Start packet capture
            filter_rule = "tcp" if filter_ot else None
            sniff(prn=packet_handler, timeout=duration, filter=filter_rule, store=False, iface=interface)
            
        except PermissionError:
            print("\n❌ Onvoldoende rechten! Run als administrator/root:")
            print("   Linux/Mac: sudo python network_scanner.py")
            print("   Windows: Run als Administrator")
            return []
        except Exception as e:
            print(f"\n❌ Fout tijdens passive scan: {e}")
            return []
        
        # Converteer naar lijst
        result = []
        for ip, info in discovered.items():
            device = {
                'ip': ip,
                'protocols': list(info['protocols']),
                'open_ports': list(info['ports']),
                'packet_count': info['packet_count'],
                'first_seen': info['first_seen'].strftime('%H:%M:%S'),
                'last_seen': info['last_seen'].strftime('%H:%M:%S'),
                'device_type': self._identify_device_type(info['ports']),
                'scan_type': 'passive'
            }
            result.append(device)
        
        print(f"\n\n✓ Passieve scan compleet! {len(result)} OT devices gedetecteerd.\n")
        self.discovered_devices = result
        return result
    
    def _scan_siemens_plc(self, ip_address, rack=0, slot=1, password=None):
        """
        Scan Siemens S7 PLC en haal device informatie op
        Ondersteunt password-protected PLCs
        """
        if not SNAP7_AVAILABLE:
            return None
        
        print(f"    Verbinden met Siemens PLC op {ip_address}...")
        
        try:
            client = snap7.client.Client()
            
            # Probeer te verbinden
            client.connect(ip_address, rack, slot)
            
            if not client.get_connected():
                print(f"    ❌ Kan niet verbinden met PLC")
                return None
            
            # Als password vereist is
            if password:
                try:
                    client.set_session_password(password)
                    print(f"    ✓ Authenticated met password")
                except Exception as e:
                    print(f"    ⚠ Password authenticatie mislukt: {e}")
            
            plc_info = {}
            
            # Haal CPU informatie op
            try:
                cpu_info = client.get_cpu_info()
                plc_info['device_type'] = 'Siemens PLC'
                plc_info['vendor'] = 'Siemens'
                plc_info['model'] = cpu_info.ModuleTypeName.decode('utf-8').strip()
                plc_info['serial'] = cpu_info.SerialNumber.decode('utf-8').strip()
                plc_info['module_name'] = cpu_info.ASName.decode('utf-8').strip()
                
                print(f"    ✓ Model: {plc_info['model']}")
                print(f"    ✓ Serial: {plc_info['serial']}")
                
            except Exception as e:
                print(f"    ⚠ Kan CPU info niet ophalen: {e}")
            
            # Haal PLC status op
            try:
                status = client.get_cpu_state()
                status_map = {
                    0: 'Unknown',
                    4: 'Stop',
                    8: 'Run'
                }
                plc_info['status'] = status_map.get(status, f'Unknown ({status})')
                print(f"    ✓ Status: {plc_info['status']}")
                
            except Exception as e:
                print(f"    ⚠ Kan status niet ophalen: {e}")
            
            # Haal firmware versie op
            try:
                order_code = client.get_order_code()
                plc_info['firmware'] = order_code.decode('utf-8').strip()
                print(f"    ✓ Firmware: {plc_info['firmware']}")
            except:
                pass
            
            client.disconnect()
            return plc_info
            
        except Exception as e:
            print(f"    ❌ PLC scan fout: {e}")
            return None
    
    def scan_siemens_with_auth(self, ip_address, username=None, password=None, rack=0, slot=1):
        """
        Specifieke functie voor Siemens PLC met authenticatie
        """
        return self._scan_siemens_plc(ip_address, rack, slot, password)
    
    def _is_host_alive(self, ip, timeout=1):
        """Check of host online is"""
        try:
            # Probeer TCP connect op algemene poort
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 102))  # S7Comm poort
            sock.close()
            if result == 0:
                return True
            
            # Alternatief: probeer andere OT poorten
            for port in [502, 2222, 44818]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            
            return False
        except:
            return False
    
    def _scan_ot_ports(self, ip, timeout=2):
        """Scan specifieke OT/ICS poorten"""
        open_ports = []
        
        for port in self.protocols.keys():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def _get_mac_address(self, ip):
        """Haal MAC adres op via ARP"""
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=1, verbose=0)[0]
            
            if result:
                return result[0][1].hwsrc
        except:
            pass
        return "Unknown"
    
    def _get_hostname(self, ip):
        """Haal hostname op"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def _identify_device_type(self, ports):
        """Identificeer device type op basis van open poorten"""
        if 102 in ports:
            return "Siemens PLC"
        elif 502 in ports:
            return "Modbus Device (PLC/RTU)"
        elif 2222 in ports or 44818 in ports:
            return "Rockwell PLC"
        elif 4840 in ports:
            return "OPC UA Server"
        elif 20000 in ports:
            return "DNP3 Device (RTU/IED)"
        elif 1911 in ports:
            return "Niagara Controller"
        elif 5007 in ports:
            return "Siemens HMI/SCADA"
        elif 34962 in ports or 34964 in ports:
            return "Profinet Device"
        else:
            return "Unknown OT Device"
    
    def _is_local_ip(self, ip):
        """Check of IP lokaal is"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def display_results(self, devices):
        """Toon scan resultaten"""
        if not devices:
            print("\nGeen devices gevonden.\n")
            return
        
        print("\n" + "=" * 100)
        print(" " * 35 + "SCAN RESULTATEN")
        print("=" * 100)
        print(f"\n{'IP Address':<16} {'Device Type':<25} {'Protocols':<30} {'Status':<15}")
        print("-" * 100)
        
        for device in devices:
            protocols = ', '.join(device.get('protocols', [])) if device.get('protocols') else 'N/A'
            status = device.get('status', device.get('scan_type', 'Unknown'))
            
            print(f"{device['ip']:<16} {device['device_type']:<25} {protocols:<30} {status:<15}")
        
        print("-" * 100)
        print(f"Totaal: {len(devices)} devices\n")
    
    def export_to_assets(self, devices):
        """Converteer scan resultaten naar asset formaat"""
        assets = []
        
        for idx, device in enumerate(devices, 1):
            asset_id = f"SCAN-{idx:03d}"
            
            # Bepaal brand op basis van device type
            brand = "Unknown"
            if "Siemens" in device['device_type']:
                brand = "Siemens"
            elif "Rockwell" in device['device_type']:
                brand = "Rockwell"
            elif "Schneider" in device['device_type']:
                brand = "Schneider"
            elif "Modbus" in device['device_type']:
                brand = "Generic Modbus"
            
            asset = {
                'id': device.get('serial', asset_id),
                'type': self._map_to_asset_type(device['device_type']),
                'ip': device['ip'],
                'brand': device.get('vendor', brand),
                'model': device.get('model', device['device_type']),
                'firmware': device.get('firmware', 'Unknown'),
                'location': f"Discovered via {device.get('scan_type', 'scan')}",
                'status': device.get('status', 'active'),
                'risk_level': 'unknown'
            }
            
            assets.append(asset)
        
        return assets
    
    def _map_to_asset_type(self, device_type):
        """Map device type naar asset type"""
        if "PLC" in device_type:
            return "PLC"
        elif "HMI" in device_type or "SCADA" in device_type:
            return "HMI"
        elif "RTU" in device_type or "DNP3" in device_type:
            return "RTU"
        elif "OPC" in device_type:
            return "SCADA"
        else:
            return "IIoT"

def main():
    """Test de scanner"""
    scanner = NetworkScanner()
    
    print("\n" + "=" * 60)
    print(" " * 15 + "OT NETWORK SCANNER TEST")
    print("=" * 60)
    print("\n1. Actieve scan")
    print("2. Passieve scan")
    print("3. Scan Siemens PLC (met wachtwoord)")
    print("4. Afsluiten")
    
    choice = input("\nSelecteer optie (1-4): ").strip()
    
    if choice == '1':
        network = input("\nNetwerk range (bijv. 192.168.1.0/24): ").strip()
        if not network:
            network = "192.168.1.0/24"
        
        devices = scanner.active_scan(network, timeout=2)
        scanner.display_results(devices)
        
        if devices:
            export = input("\nExporteer naar assets? (j/n): ").strip().lower()
            if export == 'j':
                assets = scanner.export_to_assets(devices)
                print(f"\n✓ {len(assets)} assets klaar voor export")
        
    elif choice == '2':
        duration = input("\nScan duur in seconden (standaard 60): ").strip()
        duration = int(duration) if duration else 60
        
        devices = scanner.passive_scan(duration=duration)
        scanner.display_results(devices)
        
    elif choice == '3':
        if not SNAP7_AVAILABLE:
            print("\n❌ snap7 niet geïnstalleerd!")
            print("Installeer met: pip install python-snap7")
            return
        
        ip = input("\nPLC IP adres: ").strip()
        password = input("Password (laat leeg als geen): ").strip()
        password = password if password else None
        
        plc_info = scanner._scan_siemens_plc(ip, password=password)
        if plc_info:
            print("\n✓ PLC informatie succesvol opgehaald")
    
    elif choice == '4':
        print("\nTot ziens!")

if __name__ == "__main__":
    main()