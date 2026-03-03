import argparse
import csv
import datetime
from collections import defaultdict, Counter

from pyfiglet import Figlet
from colorama import Fore, Style, init


FAIL_THRESHOLD = 5          # min failed attempts to trigger alert
WINDOW_MINUTES = 5          # time window for counting failures
SUCCESS_AFTER_FAIL_MIN = 3  # min failures before a success to flag

SUSPICIOUS_LOG = "suspicious_ssh_ips.log"
EVENTS_CSV = "ssh_events.csv"


init(autoreset=True)


def banner() -> None:
    """Display SSH / DETECT banner using pyfiglet + colorama."""
    f = Figlet(font="big")

    ssh_text = f.renderText("SSH")
    detect_text = f.renderText("DETECT")

    print(Fore.CYAN + ssh_text)
    print(Fore.RED + detect_text)
    print(Fore.WHITE + "SSH BRUTE-FORCE DETECTION LAB")
    print(Fore.WHITE + "by yexploit")
    print(Style.RESET_ALL)


def parse_auth_line(line: str):
    """Parse a typical /var/log/auth.log SSH line."""
    if "sshd" not in line:
        return None

    ts_str = line[:15]
    try:
        now = datetime.datetime.now()
        ts = datetime.datetime.strptime(f"{ts_str} {now.year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None

    outcome = None
    if "Failed password for" in line:
        outcome = "fail"
    elif "Accepted password for" in line:
        outcome = "success"
    else:
        return None

    parts = line.split()
    user = None
    src_ip = None

    try:
        idx_for = parts.index("for")
        user = parts[idx_for + 1]
    except (ValueError, IndexError):
        pass

    try:
        idx_from = parts.index("from")
        src_ip = parts[idx_from + 1]
    except (ValueError, IndexError):
        pass

    if not src_ip:
        return None

    return {
        "timestamp": ts,
        "user": user or "-",
        "src_ip": src_ip,
        "outcome": outcome,
    }


def write_event_csv_header(path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "user", "src_ip", "outcome"])


def append_event(path: str, event):
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                event["user"],
                event["src_ip"],
                event["outcome"],
            ]
        )


def log_suspicious(ip: str, reason: str):
    with open(SUSPICIOUS_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now().isoformat()} {ip} - {reason}\n")


def analyze_auth_log(path: str):
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_auth_line(line)
            if parsed:
                events.append(parsed)

    if not events:
        print("No SSH auth events parsed from log.")
        return

    events.sort(key=lambda e: e["timestamp"])

    write_event_csv_header(EVENTS_CSV)
    for e in events:
        append_event(EVENTS_CSV, e)

    window = datetime.timedelta(minutes=WINDOW_MINUTES)
    fail_events_by_ip = defaultdict(list)
    success_events_by_ip = defaultdict(list)

    for e in events:
        if e["outcome"] == "fail":
            fail_events_by_ip[e["src_ip"]].append(e)
        elif e["outcome"] == "success":
            success_events_by_ip[e["src_ip"]].append(e)

    print("=== SSH Brute-Force Detection Report ===")

    for ip, fails in fail_events_by_ip.items():
        start_idx = 0
        for i, event in enumerate(fails):
            while event["timestamp"] - fails[start_idx]["timestamp"] > window:
                start_idx += 1
            count_in_window = i - start_idx + 1
            if count_in_window >= FAIL_THRESHOLD:
                msg = (
                    f"High failed-login rate from {ip}: "
                    f"{count_in_window} failures within {WINDOW_MINUTES} minutes "
                    f"(user {event['user']})"
                )
                print("[ALERT]", msg)
                log_suspicious(ip, msg)
                break

    for ip, successes in success_events_by_ip.items():
        fails = fail_events_by_ip.get(ip, [])
        if not fails:
            continue
        first_success_time = successes[0]["timestamp"]
        prior_fails = [e for e in fails if e["timestamp"] < first_success_time]
        if len(prior_fails) >= SUCCESS_AFTER_FAIL_MIN:
            users = [e["user"] for e in prior_fails]
            user_counts = Counter(users)
            likely_user = user_counts.most_common(1)[0][0]
            msg = (
                f"Possible credential compromise from {ip}: "
                f"{len(prior_fails)} failures followed by a success "
                f"(likely user {likely_user})"
            )
            print("[ALERT]", msg)
            log_suspicious(ip, msg)

    print("Analysis complete. Events written to", EVENTS_CSV)


def main():
    banner()
    parser = argparse.ArgumentParser(description="SSH Brute-Force Detection from auth.log")
    parser.add_argument("-f", "--file", required=True, help="Path to auth.log-style file")
    args = parser.parse_args()
    analyze_auth_log(args.file)


if __name__ == "__main__":
    main()

