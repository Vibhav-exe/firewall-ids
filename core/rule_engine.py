import sys
import subprocess


def initialize_nftables():
    """
    Initialize nftables with required table, set, and chain.
    Call this once when the IDS starts.
    """
    if sys.platform != "linux":
        print("[*] Non-Linux platform - using mock nftables")
        return
    
    commands = [
        # Create inet table (won't error if exists)
        ["nft", "add", "table", "inet", "filter"],
        
        # Create IP blocklist set with timeout support
        ["nft", "add", "set", "inet", "filter", "blocked_ips", 
         "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
        
        # Create input chain
        ["nft", "add", "chain", "inet", "filter", "input",
         "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"],
        
        # Add rule to drop packets from blocked IPs
        ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", "@blocked_ips", "drop"],
    ]
    
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False  # Don't fail if already exists
            )
            # Ignore "already exists" errors
            if result.returncode != 0 and "File exists" not in result.stderr:
                print(f"[DEBUG] nft command: {' '.join(cmd)}")
                print(f"[DEBUG] Error: {result.stderr.strip()}")
        except Exception as e:
            print(f"[WARNING] nftables init error: {e}")
    
    print("[*] ✓ nftables initialized")


def block_ip(ip: str):
    """Add an IP to nftables blocked set (Linux only)."""
    if sys.platform == "linux":
        result = subprocess.run(
            [
                "nft", "add", "element", "inet", "filter",
                "blocked_ips", f"{{ {ip} timeout 10m }}"
            ],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[BLOCKED] {ip} added to nftables (10 min timeout)")
        else:
            print(f"[WARN] nft block failed for {ip}: {result.stderr.strip()}")
    else:
        from mock.mock_nft import block_ip as mock_block
        mock_block(ip)


def unblock_ip(ip: str):
    """Remove an IP from nftables blocked set manually."""
    if sys.platform == "linux":
        result = subprocess.run(
            [
                "nft", "delete", "element", "inet", "filter",
                "blocked_ips", f"{{ {ip} }}"
            ],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[UNBLOCKED] {ip} removed from nftables")
        else:
            print(f"[WARN] nft unblock failed for {ip}: {result.stderr.strip()}")
    else:
        from mock.mock_nft import unblock_ip as mock_unblock
        mock_unblock(ip)


def list_blocked():
    """List all currently blocked IPs."""
    if sys.platform == "linux":
        result = subprocess.run(
            ["nft", "list", "set", "inet", "filter", "blocked_ips"],
            capture_output=True, text=True
        )
        print(result.stdout)
    else:
        from mock.mock_nft import list_blocked as mock_list
        mock_list()


def flush_blocked():
    """Clear all blocked IPs from the set."""
    if sys.platform == "linux":
        result = subprocess.run(
            ["nft", "flush", "set", "inet", "filter", "blocked_ips"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[*] All blocked IPs flushed.")
        else:
            print(f"[WARN] Flush failed: {result.stderr.strip()}")
    else:
        from mock.mock_nft import flush_blocked as mock_flush
        mock_flush()


def cleanup_nftables():
    """Remove all IDS-related nftables rules. Use when stopping the IDS."""
    if sys.platform == "linux":
        result = subprocess.run(
            ["nft", "delete", "table", "inet", "filter"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            print("[*] ✓ nftables rules cleaned up")
        else:
            print(f"[DEBUG] Cleanup: {result.stderr.strip()}")
    else:
        print("[*] Mock cleanup (non-Linux)")


# For testing/manual management
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: sudo python3 rule_engine.py [command]")
        print("\nCommands:")
        print("  init              - Initialize nftables")
        print("  list              - List blocked IPs")
        print("  block <IP>        - Block an IP address")
        print("  unblock <IP>      - Unblock an IP address")
        print("  flush             - Clear all blocked IPs")
        print("  cleanup           - Remove all nftables rules")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "init":
        initialize_nftables()
    elif command == "list":
        list_blocked()
    elif command == "block" and len(sys.argv) > 2:
        initialize_nftables()  # Ensure it exists first
        block_ip(sys.argv[2])
    elif command == "unblock" and len(sys.argv) > 2:
        unblock_ip(sys.argv[2])
    elif command == "flush":
        flush_blocked()
    elif command == "cleanup":
        cleanup_nftables()
    else:
        print(f"Unknown command or missing argument: {command}")