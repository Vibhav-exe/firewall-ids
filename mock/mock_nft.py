blocked = set()

def block_ip(ip: str):
    blocked.add(ip)
    print(f"[MOCK] Blocked: {ip} | Total blocked: {len(blocked)}")

def unblock_ip(ip: str):
    blocked.discard(ip)
    print(f"[MOCK] Unblocked: {ip}")

def list_blocked():
    print(f"[MOCK] Currently blocked IPs: {blocked}")

def flush_blocked():
    blocked.clear()
    print("[MOCK] All IPs unblocked.")
