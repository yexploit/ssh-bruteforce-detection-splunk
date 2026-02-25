import csv
import datetime
from collections import defaultdict, Counter

import matplotlib.pyplot as plt


EVENTS_CSV = "ssh_events.csv"


def parse_time(ts_str: str) -> datetime.datetime:
    return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def load_events(path: str = EVENTS_CSV):
    times_fail = []
    src_ips_fail = []

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_time(row["timestamp"])
            if row["outcome"] == "fail":
                times_fail.append(ts)
                src_ips_fail.append(row["src_ip"])

    return times_fail, src_ips_fail


def plot_failures_over_time(times):
    counts_per_minute = defaultdict(int)
    for t in times:
        bucket = t.replace(second=0, microsecond=0)
        counts_per_minute[bucket] += 1

    xs = sorted(counts_per_minute.keys())
    ys = [counts_per_minute[x] for x in xs]

    plt.figure(figsize=(10, 4))
    plt.plot(xs, ys, marker="o")
    plt.title("SSH Failed Logins Over Time")
    plt.xlabel("Time (per minute)")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def plot_top_attackers(src_ips, top_n: int = 10):
    counts = Counter(src_ips)
    most_common = counts.most_common(top_n)
    if not most_common:
        print("No failed attempts to plot.")
        return

    labels = [ip for ip, _ in most_common]
    values = [c for _, c in most_common]

    plt.figure(figsize=(8, 4))
    plt.bar(labels, values)
    plt.title("Top SSH Brute-Force Source IPs")
    plt.xlabel("Source IP")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def main():
    try:
        times_fail, src_ips_fail = load_events()
    except FileNotFoundError:
        print("ssh_events.csv not found. Run ssh_bruteforce_analyzer.py first.")
        return

    if not times_fail:
        print("No failed SSH attempts found in events CSV.")
        return

    plot_failures_over_time(times_fail)
    plot_top_attackers(src_ips_fail)


if __name__ == "__main__":
    main()

