## SSH Brute-Force Detection in Splunk

This project simulates **SSH brute-force attacks** in a controlled lab and builds **Splunk-based detections and dashboards** to identify credential abuse patterns from `auth.log`.

The environment is designed for **defensive, educational use only** and should be deployed strictly in an isolated lab:

- **Attacker**: Kali Linux (running Nmap / Metasploit brute-force modules)
- **Target**: Linux server (e.g., Metasploitable or Ubuntu) with OpenSSH enabled
- **SIEM**: Splunk instance ingesting `/var/log/auth.log` from the target

---

### 1. Lab Overview

1. Configure an SSH-enabled Linux victim VM and a Kali attacker VM on an isolated network (host-only/internal).
2. Generate SSH brute-force traffic using:
   - Nmap NSE scripts (e.g., `ssh-brute`)
   - Or Metasploit auxiliary modules (e.g., `auxiliary/scanner/ssh/ssh_login`)
3. Forward the victim's `/var/log/auth.log` into Splunk (e.g., via universal forwarder or file monitor).
4. Use Splunk SPL searches and this repo’s Python analyzer to detect:
   - High-rate failed SSH logins
   - Repeated failures followed by a success (possible credential compromise)

Full academic write-up: `ssh_bruteforce_detection_study.md`.

---

### 2. Repository Structure

- `ssh_bruteforce_detection_study.md` – full report (intro, methodology, SPL queries, results).
- `ssh_bruteforce_analyzer.py` – Python log analyzer for `auth.log`.
- `plot_ssh_events.py` – matplotlib visualization of failed attempts and top attacking IPs.
- `splunk_searches_spl.txt` – ready-to-use Splunk SPL searches for detections and dashboards.

---

### 3. Quick Start

1. Collect a copy of `/var/log/auth.log` from your lab SSH server into this folder.
2. Run:

```bash
python3 ssh_bruteforce_analyzer.py -f auth.log
```

3. Then visualize:

```bash
python3 plot_ssh_events.py
```

For full instructions, see the report file.

