def create_asset(asset_id, asset_type, ip_address, location):
    asset = {
        'id': asset_id,
        'type': asset_type.upper(),
        'ip': ip_address,
        'location': location,
        'status': 'active',
        'risk_level': 'unknown'
    }
    return asset

def display_assets(assets):
    """Toon alle assets in een geformatteerde tabel"""
    if not assets:
        print("\nGeen assets in inventaris\n")
        return

    # De print-logica moet HIER staan (ingesprongen)
    print("\n" + "=" * 85)
    print(" " * 30 + "OT ASSET INVENTORY")
    print("=" * 85)
    print(f"\n{'ID':<12} {'Type':<10} {'IP Address':<16} {'Location':<25} {'Status':<10}")
    print("-" * 85)

    for asset in assets:
        print(f"{asset['id']:<12} {asset['type']:<10} {asset['ip']:<16} "
              f"{asset['location']:<25} {asset['status']:<10}")
    
    print("-" * 85)
    print(f"Totaal aantal Assets: {len(assets)}")

    # Statistieken
    types = {}
    for asset in assets:
        t = asset['type']
        types[t] = types.get(t, 0) + 1
    
    print(f"\nAsset Types:")
    for asset_type, count in types.items():
        print(f" • {asset_type}: {count}")

def add_asset_interactive(assets):
    print("\n" + "=" * 50)
    print("ADD NEW ASSET".center(50))
    print("=" * 50 + "\n")
    
    asset_id = input("Asset ID (bijv. PLC-001): ").strip()
    if not asset_id:
        print("Asset ID mag niet leeg zijn")
        return

    if any(a['id'] == asset_id for a in assets):
        print(f"Asset {asset_id} bestaat al!")
        return
    
    print("\nTypes: PLC, HMI, RTU, SCADA, IIoT, DCS")
    asset_type = input("Type: ").strip()
    ip_address = input("IP Adres: ").strip()
    location = input("Locatie: ").strip()
    
    asset = create_asset(asset_id, asset_type, ip_address, location)
    assets.append(asset)
    print(f"\nAsset {asset_id} succesvol toegevoegd!")

def main():
    # De lijst 'assets' wordt hier lokaal aangemaakt
    assets = [
        create_asset("PLC-001", "PLC", "192.168.1.10", "Wind Turbine 1"),
        create_asset("PLC-002", "PLC", "192.168.1.11", "Wind Turbine 2"),
        create_asset("HMI-001", "HMI", "192.168.1.50", "Control Room A"),
    ]
    
    while True:
        print("\n    MENU:")
        print(" 1. Toon alle assets")
        print(" 2. Nieuwe asset toevoegen")
        print(" 3. Afsluiten")
        
        choice = input("\nSelecteer optie (1-3): ").strip()
        
        if choice == '1':
            display_assets(assets)
        elif choice == '2':
            add_asset_interactive(assets)
        elif choice == '3':
            print(f"\nTot ziens! Totaal beheerd: {len(assets)}\n")
            break
        else:
            print("\nOngeldige keuze.")

# Zorg dat dit HELEMAAL links staat (geen spaties ervoor)
if __name__ == "__main__":
    main()