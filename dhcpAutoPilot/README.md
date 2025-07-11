# DHCP AutoPilot

An interactive script to configure an Ubuntu 24.04 server as a comprehensive network gateway with DHCP, DNS, and NAT capabilities.

## Features

- **DHCP Server**: IPv4 and/or IPv6 DHCP services
- **DNS Forwarder**: Configurable DNS forwarding for both IP versions
- **NAT Gateway**: IPv4 NAT with masquerading (IPv6 designed for end-to-end connectivity)
- **Dual Stack Support**: Choose IPv4 only, IPv6 only, or both
- **Interactive Configuration**: User-friendly prompts with input validation
- **Interactive Menu**: Main menu with configuration and restore options
- **Automatic Backup System**: All configuration files backed up before changes
- **Easy Restore**: Restore previous configurations through main menu or command line
- **Progress Tracking**: Visual progress bars for long-running operations
- **Comprehensive Logging**: Detailed logging for troubleshooting and auditing
- **Firewall Integration**: Automatic UFW configuration with proper rules
- **Error Handling**: Robust error handling with rollback capabilities

## Requirements

- Ubuntu 24.04 Server
- Root or sudo privileges
- Network interface for gateway configuration

## Installation

1. Clone or download the script:
   ```bash
   wget https://raw.githubusercontent.com/your-repo/dhcpAutoPilot/main/dhcpAutoPilot.sh
   chmod +x dhcpAutoPilot.sh
   ```

2. Run the script:
   ```bash
   sudo ./dhcpAutoPilot.sh
   ```

## Usage

### Interactive Menu
```bash
sudo ./dhcpAutoPilot.sh
```

The script will present you with a main menu:
```
Please select an option:
1) Configure new DHCP/DNS/NAT gateway
2) Restore from previous backup
3) Exit
```

### Command Line Options (Alternative)
```bash
# Direct restore mode (maintains backward compatibility)
sudo ./dhcpAutoPilot.sh --restore
```

## Configuration Options

### IP Scheme Selection
- **IPv4 Only**: Traditional IPv4 DHCP with NAT
- **IPv6 Only**: IPv6 DHCP with router advertisements
- **Dual Stack**: Both IPv4 and IPv6 configurations

### Default Settings

#### IPv4 Defaults
- Static IP: `192.168.99.1/24`
- DHCP Network: `192.168.99.0/24`
- DHCP Range: `192.168.99.2` - `192.168.99.254`
- Lease Time: `24h`
- DNS Servers: `8.8.8.8, 8.8.4.4`

#### IPv6 Defaults
- Static IP: `2001:db8::1/64`
- DHCP Network: `2001:db8::/64`
- DHCP Range: `2001:db8::100` - `2001:db8::200`
- Lease Time: `8h`
- DNS Servers: `2001:4860:4860::8888, 2001:4860:4860::8844`

## File Locations

- **Log File**: `/var/log/dhcp-gateway-setup.log`
- **Backup Directory**: `/var/backups/dhcp-gateway-config/`
- **Netplan Config**: `/etc/netplan/01-gateway.yaml`
- **dnsmasq Config**: `/etc/dnsmasq.conf`

## Services Configured

1. **netplan**: Network interface configuration
2. **dnsmasq**: DHCP and DNS services
3. **ufw**: Firewall with appropriate rules
4. **sysctl**: IP forwarding configuration

## Firewall Rules

The script automatically configures UFW with the following rules:

### IPv4 Rules
- DHCP: Ports 67/68 (UDP)
- DNS: Port 53 (TCP/UDP)
- NAT: Masquerading for configured network

### IPv6 Rules
- DHCPv6: Ports 546/547 (UDP)
- DNS: Port 53 (TCP/UDP)
- Router Advertisements: Enabled

## Backup and Restore System

### Automatic Backups
The script **automatically creates backups** before making any changes:
- **When**: Before modifying Netplan, dnsmasq, or UFW configurations
- **Where**: `/var/backups/dhcp-gateway-config/TIMESTAMP/`
- **What**: Complete configuration snapshots including:
  - All Netplan YAML files (`/etc/netplan/`)
  - dnsmasq configuration (`/etc/dnsmasq.conf`)
  - UFW firewall rules (`/etc/ufw/before.rules`)

### Restore Options

#### Option 1: Interactive Menu (Recommended)
```bash
sudo ./dhcpAutoPilot.sh
# Select "2) Restore from previous backup"
```

#### Option 2: Command Line
```bash
sudo ./dhcpAutoPilot.sh --restore
```

### Backup Structure
```
/var/backups/dhcp-gateway-config/
├── 20250111-143022/          # Latest backup
│   ├── etc/
│   │   ├── dnsmasq.conf.orig
│   │   └── ufw/
│   │       └── before.rules.orig
│   └── netplan/              # Complete netplan directory
│       └── *.yaml files
├── 20250111-141505/          # Previous backup
└── 20250111-140230/          # Older backup
```

### Restore Process
1. **Select Backup**: Choose from timestamped backup list
2. **Automatic Restoration**: Script restores all components
3. **Service Restart**: Automatically restarts affected services
4. **Verification**: Confirms successful restoration
5. **Reboot Option**: Offers system reboot for full effect

## Troubleshooting

### Check Service Status
```bash
sudo systemctl status dnsmasq
sudo ufw status
```

### View Logs
```bash
sudo tail -f /var/log/dhcp-gateway-setup.log
sudo journalctl -u dnsmasq -f
```

### Network Issues
- Ensure the selected network interface is correct
- Check that IP ranges don't conflict with existing networks
- Verify firewall rules are properly configured

### Common Issues

1. **Network Interface Not Found**: Ensure the interface exists and is up
2. **DHCP Not Working**: Check dnsmasq service status and configuration
3. **No Internet Access**: Verify NAT rules and IP forwarding settings
4. **IPv6 Issues**: Ensure IPv6 is enabled on the system

## Security Considerations

- Script requires sudo privileges for system configuration
- All changes are logged for audit purposes
- Backup system allows rollback of changes
- UFW firewall is automatically configured
- Input validation prevents malformed configurations

## IPv6 Notes

This script configures DHCPv6 and IPv6 forwarding but does **NOT** configure IPv6 NAT (NPTv6) due to:
- Complexity of NPTv6 implementation
- IPv6's design philosophy favoring end-to-end connectivity
- Most IPv6 deployments use prefix delegation instead of NAT

## License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.

**Commercial use is prohibited** without explicit written permission from the copyright holders.

For commercial licensing inquiries, please contact the repository maintainers.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on Ubuntu 24.04
5. Submit a pull request

## Support

For issues, questions, or contributions:
- Check the troubleshooting section
- Review the log files
- Open an issue on the repository

## Disclaimer

This script modifies critical network configuration files. Always:
- Test in a non-production environment first
- Ensure you have console access to the server
- Keep backups of your configurations
- Understand the changes being made

The authors are not responsible for any network disruptions or security issues resulting from the use of this script.