<div align="center">

# 🛡️ SOC / SIEM Detection Lab
### ELK Stack Attack Detection

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=3500&pause=800&color=2F81F7&center=true&vCenter=true&width=690&lines=Detection+Engineering+with+the+Elastic+Stack;SSH+Brute+Force+%7C+Recon+%7C+Backdoor+Detection;851+Failed+Logins+%7C+21+Alerts+%7C+6+MITRE+Techniques" alt="typing summary" />

<p>
  <img src="https://img.shields.io/badge/Type-Defensive%20%2F%20Blue%20Team-0A2A66?style=for-the-badge" alt="type" />
  <img src="https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-2F81F7?style=for-the-badge" alt="mitre" />
  <a href="soc_lab_report.pdf"><img src="https://img.shields.io/badge/Full%20Report-PDF-0A2A66?style=for-the-badge&logo=adobeacrobatreader&logoColor=white" alt="full report" /></a>
</p>

<p>
  <img src="https://img.shields.io/badge/Elastic%20Stack-005571?style=flat-square&logo=elasticstack&logoColor=white" alt="elastic" />
  <img src="https://img.shields.io/badge/Kibana-005571?style=flat-square&logo=kibana&logoColor=white" alt="kibana" />
  <img src="https://img.shields.io/badge/Ubuntu%2026.04%20ARM64-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="ubuntu" />
  <img src="https://img.shields.io/badge/Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white" alt="kali" />
  <img src="https://img.shields.io/badge/Nmap-2F81F7?style=flat-square" alt="nmap" />
  <img src="https://img.shields.io/badge/Hydra-2F81F7?style=flat-square" alt="hydra" />
</p>

</div>

A home security operations lab built to simulate real-world attack scenarios and practice threat detection using the Elastic Stack. The lab runs on an Apple M4 Mac Mini using UTM virtualization with two ARM64 virtual machines.

## Lab Architecture

| Component | Details |
|---|---|
| Host | Apple Mac Mini M4, 32GB RAM |
| SIEM | Ubuntu 26.04 ARM64 — Elasticsearch, Kibana, Elastic Agent |
| Attacker | Kali Linux 2023 ARM64 |
| Network | Bridged (192.168.1.0/24) |

## What Was Built

- Full ELK stack deployed on ARM64 Ubuntu — Elasticsearch, Kibana, Elastic Agent
- Custom Kibana dashboard tracking failed auth attempts, top attacking IPs, and account modification events
- Two custom detection rules written from scratch
- 1,618 Elastic prebuilt detection rules installed and enabled
- All attack activity logged, alerted on, and investigated end to end

## Attacks Simulated

| Attack | Tool | MITRE Technique |
|---|---|---|
| Network reconnaissance | Nmap | T1046 |
| SSH brute force | Hydra | T1110 |
| System discovery | Manual | T1033, T1087, T1057 |
| Backdoor account creation | Manual | T1136 |
| Privilege escalation | Manual | T1078 |

## Detection Rules Created

**SSH Brute Force Detection**
- Type: Threshold
- Query: `event.dataset : "system.auth" and event.outcome : "failure"`
- Fires when a single IP generates 5+ failed SSH logins within 5 minutes
- Severity: Medium

**Suspicious Account Creation or Modification**
- Type: Threshold
- Query: `event.dataset : "system.auth" and log.syslog.appname : "useradd" or "usermod"`
- Fires on any account creation or modification event
- Severity: High

<img src="alerts%202.png" width="720" alt="Kibana Alerts">

*The custom and prebuilt rules firing in Kibana — 21 alerts raised across the simulated attack chain.*

## Results

- 851 failed authentication attempts captured
- 21 alerts fired across 3 detection rules
- Backdoor account creation detected within seconds of execution
- All 6 MITRE ATT&CK techniques successfully logged and alerted

<img src="dashboard2.png" width="720" alt="SOC Attack Detection Dashboard">

*The SOC attack-detection dashboard — failed auth attempts, top attacking IPs, and account-modification events.*

## Full Report

See [soc_lab_report.pdf](soc_lab_report.pdf) for the complete write-up including forensic evidence, MITRE ATT&CK mapping, and recommendations.

## Tools & Assistance

- Elastic Stack 8.19.14 (Elasticsearch, Kibana, Elastic Agent, Filebeat)
- Kali Linux 2023
- Nmap
- Hydra
- UTM (Apple Silicon virtualization)
- Ubuntu 26.04 ARM64
- AI assistance provided by [Claude](https://claude.ai) (Anthropic) during lab development and documentation.

## Other Labs in This Series

| Lab | Topic | Repo |
|---|---|---|
| Lab 1 | SOC/SIEM Detection | This repo |
| Lab 2 | Incident Response Simulation | [incident-response-lab](https://github.com/jsmith-sec/incident-response-lab) |
| Lab 3 | Web Application Attack | [web-app-attack-lab](https://github.com/jsmith-sec/web-app-attack-lab) |
| Lab 4 | Vulnerability Assessment | [vulnerability-assessment-lab](https://github.com/jsmith-sec/vulnerability-assessment-lab) |
| Lab 5 | Malware Analysis | [malware-analysis-lab](https://github.com/jsmith-sec/malware-analysis-lab) |
