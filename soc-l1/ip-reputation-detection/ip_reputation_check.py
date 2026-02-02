# SOC IP Reputation Check

BLACKLIST_FILE = "blacklist.txt"

def load_blacklist():
    with open(BLACKLIST_FILE, "r") as file:
        return set(ip.strip() for ip in file)

def check_ip_reputation(suspicious_ips):
    blacklist = load_blacklist()

    for ip in suspicious_ips:
        if ip in blacklist:
            print(f"[CRITICAL][BLACKLISTED IP] {ip}")
        else:
            print(f"[INFO] IP not found in blacklist: {ip}")

def main():
    # Example IPs from previous brute-force detection
    detected_ips = ["192.168.1.100", "192.168.1.101"]
    check_ip_reputation(detected_ips)

if __name__ == "__main__":
    main()
