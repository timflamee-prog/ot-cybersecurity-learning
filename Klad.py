#!/usr/bin/env python3
"""
Modbus TCP Test Script
Tests OpenPLC via Modbus protocol
"""
from pymodbus.client import ModbusTcpClient
import time

# OpenPLC connection
PLC_IP = "192.168.100.20"
PLC_PORT = 502

def test_connection():
    """Test basic connection"""
    print(f"Connecting to OpenPLC at {PLC_IP}:{PLC_PORT}...")
    
    client = ModbusTcpClient(PLC_IP, 
    
    port=PLC_PORT)
    if client.connect():
        print("Connection successful!")
        client.close()
        return True
    else:
        print("Connection failed!")
        return False

def read_coils():
    """Read coil status (outputs)"""
    print("\nReading coils...")
    
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    client.connect()
    
    # Read coils 0-7
    result = client.read_coils(address=0, count=8)
    if not result.isError():
       print("Coil States:")
    for i, value in enumerate(result.bits[:8]):
        status = "ON" if value else "OFF"
        print(f" Coil {i} (%QX0.{i}): {status}")
    else:
        print("Error reading coils")
    client.close()
    
def write_coil(address, value):
    """Write to a single coil"""
    print(f"\nWriting coil {address} = {value}...")
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    client.connect()
    result = client.write_coil(address, value)
    if not result.isError():
        print(f"Coil {address} set to {'ON' if value else 'OFF'}")
    else:
        print(f"Error writing coil {address}")
    client.close()

def blink_test():
    """Blink output coil"""
    print("\nBlink test (Coil 0)...")
    
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    client.connect()
    
    for i in range(5):
        # Turn ON
        client.write_coil(0, True)
        print(f" Cycle {i+1}: ON", end=" ")
        time.sleep(0.5)
        
        # Turn OFF
        client.write_coil(0, False)
        print("OFF")
        time.sleep(0.5)
        client.close()
        print("Blink test complete!")
        
def main():
    print("="*50)
    print("OpenPLC Modbus Test Script")
    print("="*50)
    
    # Test connection
    if not test_connection():
        print("Cannot connect to PLC")
        return

    while True:
        print("\n" + "="*50)
        print("1. Read all coils")
        print("2. Write coil ON")
        print("3. Write coil OFF")
        print("4. Blink test")
        print("5. Exit")
        
        choice = input("\nSelect (1-5): ").strip()
        
        if choice == "1":
            read_coils()
        elif choice == "2":
            addr = int(input("Coil address (0-7): "))
            write_coil(addr, True)
        elif choice == "3":
            addr = int(input("Coil address (0-7): "))
            write_coil(addr, False)
        elif choice == "4":
            blink_test()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("\nInvalid choice")
        
if __name__ == "__main__":
    main()