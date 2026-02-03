import re
from collections import defaultdict
from datetime import datetime

# =========================
# SOC CONFIGURATION
# =========================

LOG_FILE = "auth.log"

FAILED_ATTEMPT_THRESHOLD = 5        # Number of failed attempts
TIME_WINDOW_MINUTES = 5             # Time window for correlation


# =========================
# LOG PARSING
# =========================

def parse_auth_log(log_file):
    """
    Parses auth.log and extracts failed and successful login events per IP.
    """
    failed_attempts = defaultdict(list)
    successful_logins = defaultdict(list)

    # Failed login pattern
    failed_pattern = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from (\d+\.\d+\.\d+\.\d+)"
    )

    # Successful login pattern
    success_pattern = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password.*from (\d+\.\d+\.\d+\.\d+)"
    )

    try:
        with open(log_file, "r") as file:
            for line in file:
                failed_match = failed_pattern.search(line)
                success_match = success_pattern.search(line)

                if failed_match:
                    timestamp = datetime.strptime(
                        failed_match.group(1), "%b %d %H:%M:%S"
                    )
                    ip = failed_match.group(2)
                    failed_attempts[ip].append(timestamp)

                if success_match:
                    timestamp = datetime.strptime(
                        success_match.group(1), "%b %d %H:%M:%S"
                    )
                    ip = success_match.group(2)
                    successful_logins[ip].append(timestamp)

    except FileNotFoundError:
        print(f"[ERROR] Log file '{log_file}' not found.")
        return None, None

    return failed_attempts, successful_logins


# =========================
# ACCOUNT COMPROMISE LOGIC
# =========================

def detect_account_compromise(failed_attempts, successful_logins):
    """
    Detects potential account compromise by correlating failed attempts
    followed by a successful login from the same IP.
    """
    for ip in failed_attempts:
        if ip not in successful_logins:
            continue

        failed_times = sorted(failed_attempts[ip])
        success_times = sorted(successful_logins[ip])

        for success_time in success_times:
            count = 0

            for fail_time in failed_times:
                time_diff = (success_time - fail_time).total_seconds() / 60

                if 0 <= time_diff <= TIME_WINDOW_MINUTES:
                    count += 1

            if count >= FAILED_ATTEMPT_THRESHOLD:
                print(
                    f"[CRITICAL][ACCOUNT COMPROMISE] "
                    f"IP: {ip} | "
                    f"{count} failed attempts followed by SUCCESSFUL login at {success_time.time()}"
                )
                break


# =========================
# MAIN
# =========================

def main():
    failed_attempts, successful_logins = parse_auth_log(LOG_FILE)

    if not failed_attempts and not successful_logins:
        print("[INFO] No authentication events detected.")
        return

    detect_account_compromise(failed_attempts, successful_logins)


if __name__ == "__main__":
    main()

