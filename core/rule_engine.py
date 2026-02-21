import sys
import subprocess


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
