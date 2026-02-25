## SSH Brute-Force Detection in Splunk

### 1. Introduction

SSH brute-force attacks are a common technique used by adversaries and automated bots to obtain unauthorized access to remote systems by repeatedly guessing usernames and passwords. In many organizations, evidence of such attempts is visible in system authentication logs (e.g., `/var/log/auth.log`) and in SIEM platforms such as Splunk.

This project presents a controlled, lab-based study of SSH brute-force detection using Splunk and a complementary Python analyzer. The goal is to simulate brute-force activity against an SSH server, ingest the resulting logs into Splunk, design SPL-based detections and dashboards, and implement an offline analyzer that can detect brute-force behavior directly from `auth.log`. All experiments are intended solely for defensive, educational purposes in an isolated lab environment.

---

### 2. Lab Architecture and Environment

#### 2.1 Lab Components

- **Attacker VM**  
  - Kali Linux  
  - Tools: Nmap (with NSE scripts), Metasploit  
  - Role: Generate SSH brute-force attempts against the victim.

- **Victim VM**  
  - Linux server (e.g., Ubuntu, Metasploitable 2)  
  - Services: OpenSSH server running and exposed on port 22  
  - Logs: `/var/log/auth.log` (or `/var/log/secure` on some distributions).

- **SIEM / Analysis VM**  
  - Splunk Enterprise or Splunk Free instance  
  - Ingests the victim’s `auth.log` (via Universal Forwarder, file monitor, or manual uploads).  
  - Hosts searches, dashboards, and alerts.

All machines are placed on a **Host-only** or **Internal** virtual network to ensure isolation from production or public networks.

#### 2.2 Network Layout (Textual)

Example host-only network:

- Network: `192.168.57.0/24`
- Kali (attacker): `192.168.57.10`
- Victim (SSH server): `192.168.57.20`
- Splunk/analysis VM (optional separate host): `192.168.57.30`

The SSH victim listens on port 22. Kali targets this service using brute-force tools. Splunk ingests the victim’s `auth.log` and runs detections.

#### 2.3 Safety and Isolation

- Use strong, unique passwords on any real or host systems; limit experiments to disposable lab VMs.  
- Do not expose the victim’s SSH server to the Internet during brute-force simulations.  
- Keep the virtual network in Host-only/Internal mode; avoid bridged networking while running attacks.  
- Perform experiments only on systems you own or are explicitly authorized to test.

---

### 3. SSH Brute-Force Simulation

#### 3.1 Attack Generation (Conceptual)

In the lab, brute-force behavior can be generated using:

- **Nmap NSE**:
  - Example script: `ssh-brute`  
  - Conceptual command: `nmap --script ssh-brute -p 22 192.168.57.20`

- **Metasploit**:
  - Module: `auxiliary/scanner/ssh/ssh_login`  
  - Configure RHOSTS (victim IP), RPORT (22), USER_FILE or USERNAME, PASS_FILE or PASSWORD.

The attack tools repeatedly attempt SSH logins with different username/password combinations. On the victim, each failed attempt is logged in `/var/log/auth.log` with lines similar to:

```text
Jan 10 10:00:01 victim sshd[1234]: Failed password for invalid user admin from 192.168.57.10 port 54321 ssh2
Jan 10 10:00:05 victim sshd[1234]: Failed password for root from 192.168.57.10 port 54322 ssh2
```

If a correct credential is eventually guessed, a successful login entry appears:

```text
Jan 10 10:00:30 victim sshd[1234]: Accepted password for ubuntu from 192.168.57.10 port 54325 ssh2
```

#### 3.2 Log Characteristics

Key elements in `auth.log` related to brute-force:

- Timestamp (e.g., `Jan 10 10:00:01`)  
- Process (`sshd`)  
- Outcome:
  - `Failed password for ... from <IP>`  
  - `Accepted password for ... from <IP>`  
- Username (valid or invalid)  
- Source IP and port

Brute-force behavior is characterized by:

- Many failed attempts from the same IP in a short period.  
- Attempts against multiple usernames.  
- Potentially a success after numerous failures from the same IP.

---

### 4. Splunk Ingestion and Detection

#### 4.1 Ingesting `auth.log` into Splunk

There are several options to get `auth.log` into Splunk:

- Install a **Splunk Universal Forwarder** on the victim and configure an input for `/var/log/auth.log`.  
- On the Splunk server, configure a file monitor for an NFS/SMB-mounted copy of the log.  
- Manually upload log samples as test data in Splunk’s Search & Reporting app.

Set the sourcetype appropriately (e.g., `linux_secure` or a custom sourcetype for SSH logs).

#### 4.2 SPL Queries for Detection

The file `splunk_searches_spl.txt` in this project contains reusable SPL searches. Examples:

- **Basic failed SSH events**:

```spl
index=lab sshd "Failed password for"
| rex "Failed password for(?: invalid user)? (?<user>\\S+) from (?<src_ip>\\S+)"
| stats count by _time, host, user, src_ip
```

- **Brute-force detection (many failures from same IP in 5 minutes)**:

```spl
index=lab sshd "Failed password for"
| rex "Failed password for(?: invalid user)? (?<user>\\S+) from (?<src_ip>\\S+)"
| bucket _time span=5m
| stats count AS fail_count values(user) AS users BY _time, src_ip
| where fail_count >= 5
| sort - fail_count
```

- **Success after multiple failures (possible compromise)**:

```spl
index=lab sshd ("Failed password for" OR "Accepted password for")
| rex " (?<action>Failed|Accepted) password for(?: invalid user)? (?<user>\\S+) from (?<src_ip>\\S+)"
| eval outcome=if(action="Failed","fail","success")
| bucket _time span=5m
| stats
    count(eval(outcome="fail")) AS fail_count
    count(eval(outcome="success")) AS success_count
    values(user) AS users
  BY _time, src_ip
| where fail_count >= 3 AND success_count >= 1
| sort - fail_count, success_count
```

#### 4.3 Dashboards

Using the searches above, Splunk dashboards can visualize:

- **Failed SSH logins over time** using `timechart span=1m count`.  
- **Top attacking IPs** using `top src_ip`.  
- **Top targeted usernames** using `top user`.  

These panels provide both high-level trends and detailed attack context.

---

### 5. Python Log Analyzer

#### 5.1 Goals

The Python script `ssh_bruteforce_analyzer.py` provides an offline analysis capability for environments without Splunk, or for cross-checking Splunk detections. It:

- Parses `auth.log` lines related to SSH authentication.  
- Normalizes events with timestamp, username, source IP, and outcome (`fail` or `success`).  
- Detects:
  - High failure rates from single IPs within a time window.  
  - Success events following multiple failures from the same IP.  
- Writes alerts to console and `suspicious_ssh_ips.log`.  
- Outputs a structured CSV (`ssh_events.csv`) for visualization.

#### 5.2 Usage

1. Copy the victim’s authentication log into the project folder:

```bash
sudo cp /var/log/auth.log ./auth.log
sudo chown "$USER":"$USER" ./auth.log
```

2. Run the analyzer:

```bash
python3 ssh_bruteforce_analyzer.py -f auth.log
```

3. Inspect:
   - Console output with `[ALERT]` lines.  
   - `suspicious_ssh_ips.log` for a summary of suspicious IPs.  
   - `ssh_events.csv` for detailed event records.

#### 5.3 Detection Logic

The analyzer uses:

- A **sliding time window** (e.g., 5 minutes) and a **failure threshold** (e.g., ≥ 5 failures) to flag IPs with high failed-login rates.  
- A second condition that flags IPs where:
  - There are several failures (e.g., ≥ 3) before the **first success** from that IP.  
  - This pattern suggests that a brute-force attempt may have eventually guessed valid credentials.

Constants at the top of the script (`FAIL_THRESHOLD`, `WINDOW_MINUTES`, `SUCCESS_AFTER_FAIL_MIN`) allow tuning.

---

### 6. Visualization

The script `plot_ssh_events.py` provides a simple CLI-based dashboard using matplotlib.

#### 6.1 Input

- Expects `ssh_events.csv` generated by `ssh_bruteforce_analyzer.py`.  
- Focuses on events with `outcome="fail"`.

#### 6.2 Plots

- **Failed attempts over time**  
  - Buckets events by minute and plots a time-series of failures.  

- **Top attacking IPs**  
  - Counts failed attempts per source IP.  
  - Draws a bar chart for the top N IPs.

Run:

```bash
python3 plot_ssh_events.py
```

---

### 7. Results (Example Narrative)

In lab tests:

- Nmap and Metasploit brute-force modules generated numerous failed SSH login attempts from the Kali VM to the victim.  
- Splunk successfully ingested the victim’s `auth.log`, and the provided SPL searches identified:
  - Source IPs with ≥ 5 failed attempts within 5-minute intervals.  
  - Source IPs that achieved at least one successful login after multiple failures.  
- The Python analyzer correctly flagged the Kali IP as suspicious for both high failure-rate and success-after-fail patterns.  
- The matplotlib dashboard visualized clear spikes in failed logins and highlighted the attacking IP among the top sources.

---

### 8. Conclusion

This project demonstrates an end-to-end approach for detecting SSH brute-force attacks using both SIEM-based (Splunk) and standalone log analysis techniques. By configuring a safe, isolated lab, generating controlled brute-force traffic, and analyzing logs with Splunk queries and Python code, we obtain a practical understanding of how credential abuse appears in authentication logs.

The study shows that simple heuristics—such as counting failures per IP in a time window and linking failures to subsequent successes—can detect brute-force behavior effectively in small environments. These methods can serve as a foundation for more advanced, production-grade detections that incorporate additional context, baselining, and machine learning.

---

### 9. Future Work

Potential extensions include:

- **Enhanced Threat Modeling**: Incorporate geoIP, user role, and endpoint criticality into detections.  
- **Machine Learning Approaches**: Train anomaly-detection models on SSH login patterns to reduce false positives.  
- **Integration with Response**: Use Splunk alert actions or SOAR playbooks to automatically block attacking IPs or disable accounts.  
- **Expanded Protocol Coverage**: Apply similar techniques to other authentication mechanisms (RDP, web logins, VPN gateways).

