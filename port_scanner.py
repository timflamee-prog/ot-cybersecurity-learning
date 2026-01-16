"""
OT Network Port Scanner Simulator
Scans common OT ports on multiple devices
"""

# Common OT ports dictionary
OT_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    502: "Modbus TCP",
    4840: "OPC-UA",
    102: "S7 Communication",
    44818: "EtherNet/IP"
}

def scan_port(ip, port):
    """
    Simulate port scan
    Returns: True if open, False if closed
    """
    # Simulation: ports 22, 80, 502 are "open"
    open_ports = [22, 80, 502]
    return port in open_ports

def scan_device(ip, ports_to_scan):
    """Scan all specified ports on a device"""
    print(f"\n{'='*60}")
    print(f"Scanning {ip}")
    print(f"{'='*60}")
    
    open_count = 0
    results = []
    
    for port in ports_to_scan:
        # Get port description
        port_desc = OT_PORTS.get(port, "Unknown Service")
        
        # Scan port
        is_open = scan_port(ip, port)
        
        if is_open:
            status = "OPEN"
            icon = "🟢"
            open_count += 1
            
            # Security warning for certain ports
            if port == 23:
                warning = " ⚠️ INSECURE - Telnet should be disabled"
            elif port == 502:
                warning = " ℹ️ Modbus detected - Verify authorization"
            else:
                warning = ""
            
            results.append({
                "port": port,
                "status": status,
                "service": port_desc,
                "warning": warning
            })
        else:
            status = "CLOSED"
            icon = "🔴"
        
        print(f"  Port {port:5d} [{port_desc:<20}] {icon} {status}")
        
        # Print warning if exists
        if is_open and port == 23:
            print(f"           ⚠️ SECURITY RISK: Telnet is insecure!")
        elif is_open and port == 502:
            print(f"           ℹ️ OT Protocol: Verify firewall rules")
    
    # Summary
    print(f"\n{'-'*60}")
    print(f"Summary: {open_count} open ports found")
    
    if open_count > 0:
        print(f"\nOpen Ports:")
        for result in results:
            print(f"  • {result['port']}: {result['service']}{result['warning']}")
    
    return open_count

def scan_network(network_prefix, start_host, end_host, ports):
    """Scan multiple devices in a network"""
    print("\n" + "="*60)
    print("OT NETWORK PORT SCANNER")
    print("="*60)
    print(f"Network: {network_prefix}.0/24")
    print(f"Hosts: {start_host}-{end_host}")
    print(f"Ports: {', '.join(map(str, ports))}")
    
    total_devices = 0
    total_open_ports = 0
    
    # Scan each host
    for host in range(start_host, end_host + 1):
        ip = f"{network_prefix}.{host}"
        total_devices += 1
        
        open_count = scan_device(ip, ports)
        total_open_ports += open_count
    
    # Final summary
    print("\n" + "="*60)
    print("SCAN COMPLETE")
    print("="*60)
    print(f"Devices scanned: {total_devices}")
    print(f"Total open ports: {total_open_ports}")
    print(f"Average open ports per device: {total_open_ports/total_devices:.1f}")
    print("="*60)

def interactive_scan():
    """Interactive scanning interface"""
    while True:
        print("\n" + "="*60)
        print("OT PORT SCANNER - INTERACTIVE MODE")
        print("="*60)
        print("\n1. Scan single device")
        print("2. Scan network range")
        print("3. Quick scan (common OT ports)")
        print("4. Full scan (all OT ports)")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == "1":
            # Single device scan
            ip = input("Enter IP address (e.g., 192.168.100.20): ").strip()
            ports_input = input("Enter ports (comma-separated, e.g., 22,80,502): ").strip()
            
            try:
                ports = [int(p.strip()) for p in ports_input.split(",")]
                scan_device(ip, ports)
            except ValueError:
                print("❌ Invalid port format")
                
        elif choice == "2":
            # Network range scan
            network = input("Enter network (e.g., 192.168.100): ").strip()
            start = int(input("Start host (e.g., 20): "))
            end = int(input("End host (e.g., 22): "))
            ports_input = input("Enter ports (comma-separated): ").strip()
            
            try:
                ports = [int(p.strip()) for p in ports_input.split(",")]
                scan_network(network, start, end, ports)
            except ValueError:
                print("❌ Invalid input")
                
        elif choice == "3":
            # Quick scan
            ip = input("Enter IP address: ").strip()
            quick_ports = [22, 80, 502]
            scan_device(ip, quick_ports)
            
        elif choice == "4":
            # Full scan
            ip = input("Enter IP address: ").strip()
            scan_device(ip, list(OT_PORTS.keys()))
            
        elif choice == "5":
            print("\n👋 Goodbye!")
            break
            
        else:
            print("\n❌ Invalid option")

def main():
    """Main function"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║          OT NETWORK PORT SCANNER SIMULATOR                ║
║                                                           ║
║  ⚠️ FOR EDUCATIONAL AND LAB USE ONLY                      ║
║  Never scan networks without permission!                 ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Demo mode
    demo = input("Run demo scan? (yes/no): ").strip().lower()
    
    if demo == "yes":
        # Demo: Scan 3 devices on production network
        scan_network("192.168.100", 20, 22, [22, 80, 443, 502, 4840])
    
    # Interactive mode
    interactive_scan()

if __name__ == "__main__":
    main()
