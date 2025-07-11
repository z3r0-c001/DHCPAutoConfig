#!/bin/bash
set -euo pipefail

# DHCP AutoPilot - Network Gateway Configuration Script
# 
# Licensed under Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License
# Copyright © 2025 CodeOne Contributors. All rights reserved.
# 
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# For the full license text, visit: https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode
# 
# You are free to:
# - Share — copy and redistribute the material in any medium or format
# - Adapt — remix, transform, and build upon the material
# 
# Under the following terms:
# - Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made
# - NonCommercial — You may not use the material for commercial purposes
# - ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions under the same license
# 
# COMMERCIAL USE PROHIBITION:
# Commercial use of this work is strictly prohibited without explicit written permission from the copyright holders.
# For commercial licensing inquiries, please contact the repository maintainers.

### dhcp-gateway.sh
### Interactive script to configure an Ubuntu 24.04 server as:
###  - DHCP server (IPv4/IPv6)
###  - DNS forwarder (IPv4/IPv6)
###  - NAT gateway (IPv4 only)
###  - Ensures system is up-to-date and required packages are installed
###
### Features:
###  - Interactive choice for IPv4, IPv6, or both.
###  - Concise prompts for configuration.
###  - Robust error handling and service checks.
###  - Logging to a file for auditing and troubleshooting.
###  - Option to restore previous configuration from backups.
###  - Modularized functions for clarity and maintenance.
###
### Usage:
###  sudo ./dhcp-gateway.sh         # To configure the gateway
###  sudo ./dhcp-gateway.sh --restore # To restore a previous configuration

# --- Configuration Constants ---
LOG_FILE="/var/log/dhcp-gateway-setup.log"
BACKUP_DIR="/var/backups/dhcp-gateway-config"
NETPLAN_DIR="/etc/netplan"
NETPLAN_CONFIG_FILE="$NETPLAN_DIR/01-gateway.yaml" # Renamed for clarity
DNSMASQ_CONF="/etc/dnsmasq.conf"
UFW_BEFORE_RULES="/etc/ufw/before.rules"
UFW_SYSCTL_CONF="/etc/ufw/sysctl.conf"
UFW_DEFAULT_CONF="/etc/default/ufw"
SYSCTL_CONF="/etc/sysctl.conf"

# --- Global Variables for chosen IP scheme and interface ---
IP_SCHEME_CHOICE="" # Will be 'ipv4', 'ipv6', or 'both'
SELECTED_IFACE=""   # The network interface chosen by the user

# --- Variables to store configuration details (populated by gather_ functions) ---
STATIC_IP_V4=""
DHCP_NET_V4=""
RANGE_START_V4=""
RANGE_END_V4=""
LEASE_TIME_V4="24h"
DNS_SERVERS_V4=""

STATIC_IP_V6=""
DHCP_NET_V6="" # For prefix
RANGE_START_V6=""
RANGE_END_V6=""
LEASE_TIME_V6="8h" # Common for IPv6
DNS_SERVERS_V6=""
DHCP_PREFIX_LEN_V6="" # Derived from DHCP_NET_V6

# --- Logging and Error Handling Functions ---

# Function to log messages to console and file
log_message() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Progress bar function
show_progress() {
    local current="$1"
    local total="$2"
    local task="$3"
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r\033[K"  # Clear current line
    printf "Progress: ["
    printf "%*s" "$filled" | tr ' ' '='
    printf "%*s" "$empty" | tr ' ' '-'
    printf "] %d%% - %s" "$percentage" "$task"
    
    if [[ $current -eq $total ]]; then
        printf "\n"
    fi
}

# Function to display error and exit
error_exit() {
    log_message "ERROR: $1"
    exit 1
}

# --- Validation Functions ---

# Generic IP validation function
validate_ip() {
    local ip="$1"
    local ip_type="$2" # 'ipv4' or 'ipv6'
    
    if [[ "$ip_type" == "ipv4" ]]; then
        if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            return 1
        fi
        IFS='.' read -r oct1 oct2 oct3 oct4 <<< "$ip"
        for octet in "$oct1" "$oct2" "$oct3" "$oct4"; do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
    elif [[ "$ip_type" == "ipv6" ]]; then
        if [[ ! "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})*$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:(:[0-9a-fA-F]{1,4}){1,7}$|^::$ ]]; then
            return 1
        fi
    fi
    return 0
}

# Generic CIDR validation function
validate_cidr() {
    local cidr="$1"
    local ip_type="$2" # 'ipv4' or 'ipv6'
    
    if [[ "$ip_type" == "ipv4" ]]; then
        if [[ ! "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
            return 1
        fi
        local ip="${cidr%/*}"
        validate_ip "$ip" "ipv4"
    elif [[ "$ip_type" == "ipv6" ]]; then
        if [[ ! "$cidr" =~ ^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?$|^::1(/[0-9]{1,3})?$|^([0-9a-fA-F]{1,4}:){1,7}:(/[0-9]{1,3})?$|^:(:[0-9a-fA-F]{1,4}){1,7}(/[0-9]{1,3})?$|^::(/[0-9]{1,3})?$ ]]; then
            return 1
        fi
        local prefix="${cidr#*/}"
        if [[ "$cidr" == *'/'* ]] && (( prefix < 0 || prefix > 128 )); then
            return 1
        fi
    fi
    return 0
}

# Backward compatibility functions
validate_ipv4() { validate_ip "$1" "ipv4"; }
validate_ipv6() { validate_ip "$1" "ipv6"; }
validate_ipv4_cidr() { validate_cidr "$1" "ipv4"; }
validate_ipv6_cidr() { validate_cidr "$1" "ipv6"; }

# Function to validate DNS servers (comma-separated IPs)
validate_dns_servers() {
    local dns_list="$1"
    local ip_type="$2" # 'ipv4' or 'ipv6'
    IFS=',' read -ra ADDRS <<< "$dns_list"
    for ip in "${ADDRS[@]}"; do
        local trimmed_ip=$(echo "$ip" | xargs)
        if ! validate_ip "$trimmed_ip" "$ip_type"; then
            return 1
        fi
    done
    return 0
}

# --- Backup Functions ---

# Create a timestamped backup directory
create_backup_timestamp() {
    echo "$(date +%Y%m%d-%H%M%S)"
}

# Unified backup function
backup_config() {
    local SOURCE="$1"
    local BACKUP_NAME="${2:-$(basename "$SOURCE")}"
    local TIMESTAMP=$(create_backup_timestamp)
    
    if [[ -d "$SOURCE" ]]; then
        local DEST="$BACKUP_DIR/$TIMESTAMP/$BACKUP_NAME"
        log_message "Backing up directory $SOURCE to $DEST..."
        mkdir -p "$DEST" || error_exit "Failed to create backup directory for $SOURCE."
        cp -R "$SOURCE"/* "$DEST/" || error_exit "Failed to copy directory $SOURCE to backup."
    elif [[ -f "$SOURCE" ]]; then
        local DEST_DIR="$BACKUP_DIR/$TIMESTAMP/$(dirname "$SOURCE")"
        log_message "Backing up file $SOURCE to $DEST_DIR..."
        mkdir -p "$DEST_DIR" || error_exit "Failed to create backup directory for $SOURCE."
        cp "$SOURCE" "$DEST_DIR/$(basename "$SOURCE").orig" || error_exit "Failed to copy $SOURCE to backup."
    else
        log_message "Warning: $SOURCE does not exist, skipping backup."
    fi
}

# Backward compatibility functions
backup_netplan() { backup_config "$NETPLAN_DIR" "netplan"; }
backup_file() { backup_config "$1"; }

# --- Generic Input Function ---

# Generic input prompt with validation
prompt_input() {
    local prompt_text="$1"
    local default_value="$2"
    local validator_func="$3"
    local validator_args="${4:-}"
    local error_msg="${5:-Invalid input format.}"
    local result=""
    
    while true; do
        read -rp "$prompt_text [$default_value]: " input
        result="${input:-$default_value}"
        if [[ -n "$validator_func" ]]; then
            if $validator_func "$result" $validator_args; then
                break
            else
                log_message "$error_msg"
            fi
        else
            break
        fi
    done
    echo "$result"
}

# --- Core Setup Functions ---

show_header() {
    clear
    cat << "EOF"
 ____  _   _  ____ ____      _         _        ____  _ _       _   
|  _ \| | | |/ ___|  _ \    / \  _   _| |_ ___ |  _ \(_) | ___ | |_ 
| | | | |_| | |   | |_) |  / _ \| | | | __/ _ \| |_) | | |/ _ \| __|
| |_| |  _  | |___|  __/  / ___ \ |_| | || (_) |  __/| | | (_) | |_ 
|____/|_| |_|\____|_|    /_/   \_\__,_|\__\___/|_|   |_|_|\___/ \__|
                                                                    
         Network Gateway Configuration Script for Ubuntu 24.04
         
         Features:
         - DHCP Server (IPv4/IPv6)
         - DNS Forwarder (IPv4/IPv6)  
         - NAT Gateway (IPv4 only)
         - Automated Backup & Restore
         - Firewall Configuration
         
===========================================================================
EOF
}

initial_setup() {
    show_header
    log_message "Log file: $LOG_FILE"
    log_message "Backup directory: $BACKUP_DIR"
    log_message ""

    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR" || error_exit "Failed to create backup directory $BACKUP_DIR."

    # Main menu choice
    log_message "Please select an option:"
    log_message "1) Configure new DHCP/DNS/NAT gateway"
    log_message "2) Restore from previous backup"
    log_message "3) Exit"

    while true; do
        read -rp "Enter your choice (1, 2, or 3): " MAIN_CHOICE
        case "$MAIN_CHOICE" in
            1) break ;;  # Continue with normal setup
            2) restore_configuration ;;  # Go to restore function
            3) log_message "Exiting..."; exit 0 ;;
            *) log_message "Invalid choice. Please enter 1, 2, or 3." ;;
        esac
    done

    # Ask user for IP scheme choice
    log_message ""
    log_message "Choose the IP scheme(s) you want to configure:"
    log_message "1) IPv4 only"
    log_message "2) IPv6 only"
    log_message "3) Both IPv4 and IPv6"

    while true; do
        read -rp "Enter your choice (1, 2, or 3): " SCHEME_CHOICE
        case "$SCHEME_CHOICE" in
            1) IP_SCHEME_CHOICE="ipv4"; break ;;
            2) IP_SCHEME_CHOICE="ipv6"; break ;;
            3) IP_SCHEME_CHOICE="both"; break ;;
            *) log_message "Invalid choice. Please enter 1, 2, or 3." ;;
        esac
    done
    log_message "Selected IP scheme: $IP_SCHEME_CHOICE"
}

system_prerequisites() {
    log_message "---"
    log_message "Updating & upgrading system packages (this may take a moment)..."
    
    show_progress 1 4 "Updating package lists..."
    apt update >> "$LOG_FILE" 2>&1 || error_exit "Failed to update package lists."
    
    show_progress 2 4 "Upgrading system packages..."
    DEBIAN_FRONTEND=noninteractive apt -y upgrade >> "$LOG_FILE" 2>&1 || error_exit "Failed to upgrade packages."
    
    show_progress 3 4 "Installing required packages..."
    apt install -y netplan.io dnsmasq ufw >> "$LOG_FILE" 2>&1 || error_exit "Failed to install required packages."
    
    show_progress 4 4 "System prerequisites completed"
    log_message "System updated and required packages installed."
}

select_network_interface() {
    log_message "---"
    log_message "Detecting network interfaces..."
    # Exclude loopback interface (lo)
    mapfile -t IFACES < <(ls /sys/class/net | grep -v lo)
    if [[ ${#IFACES[@]} -eq 0 ]]; then
        error_exit "No network interfaces detected (excluding 'lo')."
    fi

    # Loop until a confirmed interface is selected
    while true; do
        log_message "Available network interfaces:"
        select IFACE_SELECTED in "${IFACES[@]}"; do
            [[ -n "$IFACE_SELECTED" ]] && break
            log_message "Invalid selection. Please choose a number from the list."
        done
        SELECTED_IFACE="$IFACE_SELECTED"
        log_message "Selected interface: $SELECTED_IFACE"
        log_message "Current configuration for $SELECTED_IFACE:"
        ip addr show "$SELECTED_IFACE" | tee -a "$LOG_FILE" || true
        ip route show dev "$SELECTED_IFACE" | tee -a "$LOG_FILE" || true
        read -rp "Confirm configuration for '$SELECTED_IFACE'? This will overwrite its current settings. [y/N]: " CONFIRM_IFACE
        if [[ "$CONFIRM_IFACE" =~ ^[Yy]$ ]]; then
            log_message "Interface selected: $SELECTED_IFACE"
            break
        else
            log_message "Interface selection cancelled."
            read -rp "Would you like to start over and select a different interface? [y/N]: " START_OVER
            if [[ "$START_OVER" =~ ^[Yy]$ ]]; then
                continue
            else
                error_exit "Setup cancelled by user."
            fi
        fi
    done
}

gather_ipv4_config() {
    log_message "---"
    log_message "Gathering IPv4 network configuration details..."

    # Defaults
    local DEFAULT_STATIC_V4="192.168.99.1/24"
    local DEFAULT_NET_V4="192.168.99.0/24"
    local DEFAULT_DNS_V4="8.8.8.8,8.8.4.4" # Google DNS servers

    STATIC_IP_V4=$(prompt_input "Static IPv4 for this server (CIDR e.g., 192.168.99.1/24)" "$DEFAULT_STATIC_V4" "validate_ipv4_cidr" "" "Invalid IPv4 CIDR format.")
    DHCP_NET_V4=$(prompt_input "DHCPv4 network (CIDR e.g., 192.168.99.0/24)" "$DEFAULT_NET_V4" "validate_ipv4_cidr" "" "Invalid IPv4 Network CIDR format.")
    
    local NET_BASE_V4=$(echo "$DHCP_NET_V4" | cut -d. -f1-3)
    local DEFAULT_START_V4="${NET_BASE_V4}.2"
    local DEFAULT_END_V4="${NET_BASE_V4}.254"

    RANGE_START_V4=$(prompt_input "DHCPv4 range start IP" "$DEFAULT_START_V4" "validate_ipv4" "" "Invalid IPv4 address format.")
    RANGE_END_V4=$(prompt_input "DHCPv4 range end IP" "$DEFAULT_END_V4" "validate_ipv4" "" "Invalid IPv4 address format.")
    LEASE_TIME_V4=$(prompt_input "DHCPv4 lease time (e.g. 24h, 12h, 30m)" "$LEASE_TIME_V4" "" "" "")
    DNS_SERVERS_V4=$(prompt_input "DNSv4 servers (comma-separated IPs e.g., 8.8.8.8,8.8.4.4)" "$DEFAULT_DNS_V4" "validate_dns_servers" "ipv4" "Invalid DNSv4 server IP format.")

    log_message "IPv4 configuration details gathered."
}

gather_ipv6_config() {
    log_message "---"
    log_message "Gathering IPv6 network configuration details..."
    log_message "NOTE: This script configures DHCPv6 and IPv6 forwarding. It DOES NOT configure IPv6 NAT (NPTv6) due to its complexity and different design philosophy compared to IPv4 NAT. IPv6 is designed for end-to-end connectivity."

    # Defaults
    local DEFAULT_STATIC_V6="2001:db8::1/64" # Example unique local address
    local DEFAULT_DHCP_PREFIX_V6="2001:db8::/64" # Example prefix for DHCPv6
    local DEFAULT_DNS_V6="2001:4860:4860::8888,2001:4860:4860::8844" # Google Public DNSv6

    STATIC_IP_V6=$(prompt_input "Static IPv6 for this server (CIDR e.g., 2001:db8::1/64)" "$DEFAULT_STATIC_V6" "validate_ipv6_cidr" "" "Invalid IPv6 CIDR format.")
    DHCP_NET_V6=$(prompt_input "DHCPv6 network prefix (CIDR e.g., 2001:db8::/64)" "$DEFAULT_DHCP_PREFIX_V6" "validate_ipv6_cidr" "" "Invalid IPv6 Network CIDR format.")
    DHCP_PREFIX_LEN_V6="${DHCP_NET_V6#*/}" # Extract prefix length
    
    # For simplicity, we'll use a fixed range within the prefix for stateful DHCPv6
    local DEFAULT_START_V6="${DHCP_NET_V6%/64}100" # Example: 2001:db8::100
    local DEFAULT_END_V6="${DHCP_NET_V6%/64}200"  # Example: 2001:db8::200

    RANGE_START_V6=$(prompt_input "DHCPv6 range start IP" "$DEFAULT_START_V6" "validate_ipv6" "" "Invalid IPv6 address format.")
    RANGE_END_V6=$(prompt_input "DHCPv6 range end IP" "$DEFAULT_END_V6" "validate_ipv6" "" "Invalid IPv6 address format.")
    LEASE_TIME_V6=$(prompt_input "DHCPv6 lease time (e.g. 8h, 1h, 30m)" "$LEASE_TIME_V6" "" "" "")
    DNS_SERVERS_V6=$(prompt_input "DNSv6 servers (comma-separated IPs e.g., 2001:4860:4860::8888,...)" "$DEFAULT_DNS_V6" "validate_dns_servers" "ipv6" "Invalid DNSv6 server IP format.")

    log_message "IPv6 configuration details gathered."
}

confirm_final_config() {
    log_message "---"
    log_message "--- Proposed Gateway Configuration ---"
    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        log_message "  IPv4 Settings:"
        log_message "    Static IP:          $STATIC_IP_V4 (Gateway for clients)"
        log_message "    DHCPv4 Network:     $DHCP_NET_V4"
        log_message "    DHCPv4 Range:       $RANGE_START_V4 - $RANGE_END_V4 (Lease time: $LEASE_TIME_V4)"
        log_message "    DNSv4 Forwarders:   $DNS_SERVERS_V4"
    fi
    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        log_message "  IPv6 Settings:"
        log_message "    Static IP:          $STATIC_IP_V6 (Gateway for clients)"
        log_message "    DHCPv6 Network:     $DHCP_NET_V6"
        log_message "    DHCPv6 Range:       $RANGE_START_V6 - $RANGE_END_V6 (Lease time: $LEASE_TIME_V6)"
        log_message "    DNSv6 Forwarders:   $DNS_SERVERS_V6"
        log_message "    NOTE: IPv6 NAT (NPTv6) is NOT configured by this script."
    fi
    log_message "--------------------------------------"
    read -rp "Proceed with applying this configuration? [y/N]: " FINAL_CONFIRM
    if [[ ! "$FINAL_CONFIRM" =~ ^[Yy]$ ]]; then
        error_exit "Configuration cancelled by user."
    fi
}

apply_netplan_config() {
    log_message "---"
    log_message "Applying Netplan configuration for $SELECTED_IFACE..."
    
    show_progress 1 4 "Backing up existing Netplan configurations..."
    backup_netplan

    show_progress 2 4 "Building Netplan YAML configuration..."
    # Start building Netplan YAML
    NETPLAN_YAML_CONTENT="network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    $SELECTED_IFACE:\n      dhcp4: no\n      dhcp6: no\n      accept-ra: no\n"

    # Assemble addresses array
    NETPLAN_ADDRESSES=()
    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        NETPLAN_ADDRESSES+=("$STATIC_IP_V4")
    fi
    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        NETPLAN_ADDRESSES+=("$STATIC_IP_V6")
    fi

    if [[ ${#NETPLAN_ADDRESSES[@]} -gt 0 ]]; then
        # Join array elements with a comma and space for YAML format
        NETPLAN_YAML_CONTENT+="      addresses: [ $(IFS=,; echo "${NETPLAN_ADDRESSES[*]}") ]\n"
    fi

    echo -e "$NETPLAN_YAML_CONTENT" | tee "$NETPLAN_CONFIG_FILE" >> "$LOG_FILE"
    
    show_progress 3 4 "Applying Netplan configuration..."
    # Use netplan try for safer application
    if ! netplan try >> "$LOG_FILE" 2>&1; then
        rm -f "$NETPLAN_CONFIG_FILE" # Clean up problematic file
        error_exit "Netplan configuration failed or caused connectivity issues. Please review and try again."
    fi
    
    show_progress 4 4 "Netplan configuration completed"
    log_message "Netplan configuration applied successfully."
    sleep 2 # Give network a moment to settle
}

enable_ip_forwarding() {
    log_message "---"
    log_message "Enabling IP forwarding in sysctl..."
    # Ensure IP forwarding is enabled in sysctl.conf for IPv4 and/or IPv6
    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        if ! grep -q '^net.ipv4.ip_forward=1' "$SYSCTL_CONF"; then
          sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' "$SYSCTL_CONF" || error_exit "Failed to modify $SYSCTL_CONF for IPv4 forwarding."
        fi
    fi
    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        if ! grep -q '^net.ipv6.conf.all.forwarding=1' "$SYSCTL_CONF"; then
          sed -i 's/^#\?net.ipv6.conf.all.forwarding=.*/net.ipv6.conf.all.forwarding=1/' "$SYSCTL_CONF" || error_exit "Failed to modify $SYSCTL_CONF for IPv6 all forwarding."
        fi
        if ! grep -q '^net.ipv6.conf.default.forwarding=1' "$SYSCTL_CONF"; then
          sed -i 's/^#\?net.ipv6.conf.default.forwarding=.*/net.ipv6.conf.default.forwarding=1/' "$SYSCTL_CONF" || error_exit "Failed to modify $SYSCTL_CONF for IPv6 default forwarding."
        fi
    fi
    sysctl -p >> "$LOG_FILE" 2>&1 || error_exit "Failed to apply sysctl changes."
    log_message "IP forwarding enabled."
}

configure_dnsmasq_service() {
    log_message "---"
    log_message "Configuring dnsmasq..."
    
    show_progress 1 4 "Backing up existing dnsmasq configuration..."
    if [[ -f "$DNSMASQ_CONF" ]]; then
        backup_file "$DNSMASQ_CONF"
    fi

    show_progress 2 4 "Building dnsmasq configuration..."
    # Start building dnsmasq.conf content
    DNSMASQ_CONF_CONTENT="# Listen on the chosen interface only\n"
    DNSMASQ_CONF_CONTENT+="interface=$SELECTED_IFACE\n"
    DNSMASQ_CONF_CONTENT+="bind-interfaces\n\n"
    DNSMASQ_CONF_CONTENT+="# DNS forwarders\n"
    DNSMASQ_CONF_CONTENT+="no-resolv\n"

    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        local GW_IP_V4="${STATIC_IP_V4%%/*}"
        DNSMASQ_CONF_CONTENT+="$(printf '%s\n' "${DNS_SERVERS_V4//,/ }" | sed 's/^/server=/')\n"
        DNSMASQ_CONF_CONTENT+="# DHCPv4 pool\n"
        DNSMASQ_CONF_CONTENT+="dhcp-range=$RANGE_START_V4,$RANGE_END_V4,$LEASE_TIME_V4\n"
        DNSMASQ_CONF_CONTENT+="dhcp-option=option:router,${GW_IP_V4}\n"
        DNSMASQ_CONF_CONTENT+="dhcp-option=option:dns-server,${GW_IP_V4}\n\n"
    fi

    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        local GW_IP_V6="${STATIC_IP_V6%%/*}"
        DNSMASQ_CONF_CONTENT+="$(printf '%s\n' "${DNS_SERVERS_V6//,/ }" | sed 's/^/server=/')\n"
        DNSMASQ_CONF_CONTENT+="# DHCPv6 pool (Stateful DHCPv6)\n"
        DNSMASQ_CONF_CONTENT+="enable-ra\n" # Enable Router Advertisements
        DNSMASQ_CONF_CONTENT+="dhcp-range=$RANGE_START_V6,$RANGE_END_V6,$DHCP_PREFIX_LEN_V6,$LEASE_TIME_V6\n"
        DNSMASQ_CONF_CONTENT+="dhcp-option=option6:dns-server,${GW_IP_V6}\n\n" # Use server's IPv6 as DNS
    fi

    echo -e "$DNSMASQ_CONF_CONTENT" | tee "$DNSMASQ_CONF" >> "$LOG_FILE"
    
    show_progress 3 4 "Restarting and enabling dnsmasq service..."
    systemctl restart dnsmasq >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart dnsmasq. Check logs: journalctl -u dnsmasq"
    systemctl enable dnsmasq >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable dnsmasq service."
    
    show_progress 4 4 "dnsmasq configuration completed"
    log_message "dnsmasq configured and running."
}

configure_ufw_firewall() {
    log_message "---"
    log_message "Setting up UFW for Firewall/Forwarding..."

    show_progress 1 6 "Enabling IP forwarding in UFW sysctl..."
    # Enable IP forwarding in UFW sysctl for IPv4 and/or IPv6
    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        sed -i 's|^#net/ipv4/ip_forward=1|net/ipv4/ip_forward=1|' "$UFW_SYSCTL_CONF" || error_exit "Failed to modify $UFW_SYSCTL_CONF for IPv4."
    fi
    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        sed -i 's|^#net/ipv6/conf/all/forwarding=1|net/ipv6/conf/all/forwarding=1|' "$UFW_SYSCTL_CONF" || error_exit "Failed to modify $UFW_SYSCTL_CONF for IPv6 all."
        sed -i 's|^#net/ipv6/conf/default/forwarding=1|net/ipv6/conf/default/forwarding=1|' "$UFW_SYSCTL_CONF" || error_exit "Failed to modify $UFW_SYSCTL_CONF for IPv6 default."
    fi

    show_progress 2 6 "Setting UFW forward policy..."
    # Allow forwarding in UFW policy
    sed -i 's|^DEFAULT_FORWARD_POLICY=.*|DEFAULT_FORWARD_POLICY="ACCEPT"|' "$UFW_DEFAULT_CONF" || error_exit "Failed to modify $UFW_DEFAULT_CONF."

    show_progress 3 6 "Adding IPv4 NAT rules..."
    # Insert NAT rules at top of before.rules for IPv4
    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        backup_file "$UFW_BEFORE_RULES"
        # Remove existing rules added by this script to ensure idempotency
        sed -i '/# NAT table rules added by dhcp.sh/,/COMMIT/d' "$UFW_BEFORE_RULES" >> "$LOG_FILE" 2>&1 || true # `|| true` to prevent error if pattern not found

        awk -v net="$DHCP_NET_V4" -v iface="$SELECTED_IFACE" 'BEGIN {
          print "# NAT table rules added by dhcp.sh"
          print "*nat"
          print ":POSTROUTING ACCEPT [0:0]"
          print "-A POSTROUTING -s " net " -o " iface " -j MASQUERADE"
          print "COMMIT\n"
        }
        { print }
        ' "$UFW_BEFORE_RULES" > "${UFW_BEFORE_RULES}.new" || error_exit "Failed to create new UFW rules file."
        mv "${UFW_BEFORE_RULES}.new" "$UFW_BEFORE_RULES" || error_exit "Failed to move new UFW rules into place."
    fi

    show_progress 4 6 "Configuring UFW rules for DHCP/DNS traffic..."
    
    # Function to add UFW rule if it doesn't exist
    add_ufw_rule() {
        local rule_desc="$1"
        shift
        local rule_args="$@"
        
        if ! ufw status numbered | grep -q "$rule_desc"; then
            ufw $rule_args comment "$rule_desc" >> "$LOG_FILE" 2>&1 || log_message "Warning: Failed to add UFW rule: $rule_desc"
        else
            log_message "UFW rule already exists: $rule_desc"
        fi
    }
    
    # Allow DHCPv4 client (port 68) to server (port 67)
    add_ufw_rule "Allow DHCPv4 client to server" allow in on "$SELECTED_IFACE" to any port 67 proto udp
    add_ufw_rule "Allow DHCPv4 server to client" allow out on "$SELECTED_IFACE" to any port 68 proto udp
    # Allow DNS (port 53)
    add_ufw_rule "Allow DNSv4 UDP" allow in on "$SELECTED_IFACE" to any port 53 proto udp
    add_ufw_rule "Allow DNSv4 TCP" allow in on "$SELECTED_IFACE" to any port 53 proto tcp

    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        # Allow DHCPv6 client (port 546) to server (port 547)
        add_ufw_rule "Allow DHCPv6 client to server" allow in on "$SELECTED_IFACE" to any port 547 proto udp
        add_ufw_rule "Allow DHCPv6 server to client" allow out on "$SELECTED_IFACE" to any port 546 proto udp
        # Allow DNSv6 (port 53)
        add_ufw_rule "Allow DNSv6 UDP" allow in on "$SELECTED_IFACE" to any port 53 proto udp from any to any
        add_ufw_rule "Allow DNSv6 TCP" allow in on "$SELECTED_IFACE" to any port 53 proto tcp from any to any
    fi

    show_progress 5 6 "Enabling UFW and OpenSSH access..."
    # Ensure SSH remains allowed for both IPv4 and IPv6
    ufw allow OpenSSH >> "$LOG_FILE" 2>&1 || error_exit "Failed to allow OpenSSH through UFW."

    # Enable UFW (forces on if not already)
    ufw --force enable >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable UFW."
    if ! ufw status | grep -q "Status: active"; then
        error_exit "UFW is not active. Check UFW logs."
    fi
    
    show_progress 6 6 "UFW firewall configuration completed"
    log_message "UFW enabled and configured."
}

check_services() {
    log_message "---"
    log_message "Checking service statuses..."
    local dnsmasq_status=$(systemctl is-active dnsmasq)
    local ufw_status=$(ufw status | grep "Status: active")

    if [[ "$dnsmasq_status" == "active" ]]; then
        log_message "dnsmasq service is running."
    else
        log_message "dnsmasq service is NOT running. Status: $dnsmasq_status"
    fi

    if [[ -n "$ufw_status" ]]; then
        log_message "UFW is active."
    else
        log_message "UFW is NOT active."
    fi
}

final_summary_and_reboot() {
    log_message "---"
    log_message "Setup Complete!"
    log_message "Your Ubuntu server is now configured as a network gateway."
    log_message ""
    log_message "Summary of applied settings:"
    log_message "------------------------------"
    log_message "  IP Scheme:               $IP_SCHEME_CHOICE"
    log_message "  Configured Interface:    $SELECTED_IFACE"
    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        log_message "  IPv4 Static IP:          $STATIC_IP_V4"
        log_message "  IPv4 DHCP Network:       $DHCP_NET_V4"
        log_message "  IPv4 DHCP Range:         $RANGE_START_V4 - $RANGE_END_V4 (Lease: $LEASE_TIME_V4)"
        log_message "  IPv4 DNS Forwarders:     $DNS_SERVERS_V4"
        log_message "  IPv4 NAT:                Enabled"
    fi
    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        log_message "  IPv6 Static IP:          $STATIC_IP_V6"
        log_message "  IPv6 DHCP Network:       $DHCP_NET_V6"
        log_message "  IPv6 DHCP Range:         $RANGE_START_V6 - $RANGE_END_V6 (Lease: $LEASE_TIME_V6)"
        log_message "  IPv6 DNS Forwarders:     $DNS_SERVERS_V6"
        log_message "  IPv6 NAT (NPTv6):        NOT configured by this script (complex, different design)."
    fi
    log_message "------------------------------"
    log_message ""
    log_message "It is highly recommended to reboot your system for all network changes to take full effect."
    read -rp "Would you like to reboot now? [y/N]: " REBOOT_CONFIRM
    if [[ "$REBOOT_CONFIRM" =~ ^[Yy]$ ]]; then
        log_message "Rebooting..."
        reboot
    else
        log_message "Please remember to reboot your system manually later."
    fi
}

restore_configuration() {
    log_message "--- Configuration Restore Mode ---"
    log_message "Warning: This will attempt to revert network configurations."
    log_message "It's highly recommended to have console access."
    log_message "Backups are located in: $BACKUP_DIR"

    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR")" ]]; then
        error_exit "No backups found in $BACKUP_DIR. Cannot restore."
    fi

    log_message "Available backups (by timestamp):"
    mapfile -t BACKUPS < <(ls -d "$BACKUP_DIR"/*/ | xargs -n 1 basename | sort -r)

    if [[ ${#BACKUPS[@]} -eq 0 ]]; then
        error_exit "No dated backup directories found in $BACKUP_DIR."
    fi

    select BACKUP_SELECTION in "${BACKUPS[@]}"; do
        [[ -n "$BACKUP_SELECTION" ]] && break
        log_message "Invalid selection. Please choose a number from the list."
    done

    local SELECTED_BACKUP_PATH="$BACKUP_DIR/$BACKUP_SELECTION"
    log_message "Selected backup: $SELECTED_BACKUP_PATH"
    read -rp "Are you sure you want to restore from this backup? This cannot be undone. [y/N]: " CONFIRM_RESTORE
    if [[ ! "$CONFIRM_RESTORE" =~ ^[Yy]$ ]]; then
        error_exit "Restore operation cancelled by user."
    fi

    log_message "Restoring Netplan configuration..."
    if [[ -d "$SELECTED_BACKUP_PATH/etc/netplan" ]]; then
        log_message "Clearing current Netplan configuration..."
        rm -f "$NETPLAN_DIR"/*.yaml || true # Remove existing yaml files
        log_message "Copying backed up Netplan files..."
        cp -R "$SELECTED_BACKUP_PATH/etc/netplan/"* "$NETPLAN_DIR/" || error_exit "Failed to restore Netplan files."
        log_message "Applying restored Netplan configuration with 'netplan apply'..."
        if ! netplan apply >> "$LOG_FILE" 2>&1; then
            log_message "Warning: Restoring Netplan failed or caused connectivity issues. Manual intervention may be needed."
            log_message "You may need to manually run 'netplan apply' or reboot."
        else
            log_message "Netplan configuration restored and applied."
        fi
    else
        log_message "No Netplan backup found in selected timestamp. Skipping Netplan restore."
    fi

    log_message "Restoring dnsmasq configuration..."
    if [[ -f "$SELECTED_BACKUP_PATH/etc/dnsmasq.conf.orig" ]]; then
        cp "$SELECTED_BACKUP_PATH/etc/dnsmasq.conf.orig" "$DNSMASQ_CONF" || error_exit "Failed to restore dnsmasq.conf."
        log_message "dnsmasq.conf restored. Restarting service..."
        systemctl restart dnsmasq >> "$LOG_FILE" 2>&1 || log_message "Failed to restart dnsmasq after restore. Check logs."
    else
        log_message "No dnsmasq.conf backup found for this timestamp. Skipping dnsmasq restore."
    fi

    log_message "Restoring UFW before.rules..."
    if [[ -f "$SELECTED_BACKUP_PATH/etc/ufw/before.rules.orig" ]]; then
        cp "$SELECTED_BACKUP_PATH/etc/ufw/before.rules.orig" "$UFW_BEFORE_RULES" || error_exit "Failed to restore UFW before.rules."
        log_message "UFW before.rules restored."
    else
        log_message "No UFW before.rules backup found for this timestamp. Skipping UFW rules restore."
    fi

    log_message "Reloading UFW rules (if UFW is active)..."
    if ufw status | grep -q "Status: active"; then
        ufw reload >> "$LOG_FILE" 2>&1 || log_message "Failed to reload UFW. Manual intervention may be needed."
        log_message "UFW reloaded."
    else
        log_message "UFW was not active. Not reloading."
    fi

    log_message "--- Restore Complete ---"
    log_message "It is highly recommended to reboot your system to ensure all changes take full effect."
    read -rp "Would you like to reboot now? [y/N]: " REBOOT_CONFIRM
    if [[ "$REBOOT_CONFIRM" =~ ^[Yy]$ ]]; then
        log_message "Rebooting..."
        reboot
    else
        log_message "Please remember to reboot your system manually later."
    fi
    exit 0
}

# --- Main execution flow ---
main() {
    # Check if restore mode is requested (maintain backward compatibility)
    if [[ "${1:-}" == "--restore" ]]; then
        restore_configuration
    fi

    initial_setup
    system_prerequisites
    select_network_interface

    # Call configuration functions based on choice
    if [[ "$IP_SCHEME_CHOICE" == "ipv4" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        gather_ipv4_config
    fi
    if [[ "$IP_SCHEME_CHOICE" == "ipv6" || "$IP_SCHEME_CHOICE" == "both" ]]; then
        gather_ipv6_config
    fi

    confirm_final_config

    apply_netplan_config
    enable_ip_forwarding
    configure_dnsmasq_service
    configure_ufw_firewall
    check_services
    final_summary_and_reboot
}

# Call the main function
main "$@"