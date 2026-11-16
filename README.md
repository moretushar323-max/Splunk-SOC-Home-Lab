# Splunk SOC Home Lab

A hands-on home lab demonstrating Windows endpoint log collection, SIEM ingestion, failed-authentication analysis, SPL-based detection, and scheduled alerting with Splunk Enterprise.

**Author:** Tushar More

## Project overview

This lab uses a Windows endpoint, Splunk Enterprise running on Ubuntu, and Kali Linux for controlled security testing.

### Lab components

| Component | Purpose |
|---|---|
| Windows 11 | Endpoint and Windows Event Log source |
| Splunk Universal Forwarder | Collects and forwards Windows event logs |
| Ubuntu Linux | Hosts Splunk Enterprise 10.6.1.1 |
| Kali Linux | Controlled lab testing source |
| Splunk Enterprise | SIEM search, detection and alerting |

## Implemented and evidenced work

- Installed Splunk Enterprise on Ubuntu.
- Configured Splunk receiving on TCP port `9997`.
- Installed and configured Splunk Universal Forwarder on Windows.
- Collected Windows Application, System and Security event channels into `index=main`.
- Investigated Windows failed-logon Event ID `4625`.
- Built SPL to extract source IP and target username and count repeated failures.
- Configured a scheduled detection alert with a five-failure threshold.
- Verified a triggered alert in Splunk.

> Evidence note: the saved SPL screenshot shows five failed-logon events grouped by source address and account. The source IP is redacted in the public screenshot. Do not interpret Event ID 4625 alone as proof of a successful compromise.

## Architecture

```text
Windows 11 endpoint
  ├── Application logs
  ├── System logs
  └── Security logs
        |
        v
Splunk Universal Forwarder
        |
        | TCP 9997
        v
Ubuntu Linux - Splunk Enterprise 10.6.1.1
        |
        v
index=main
        |
        v
SPL detection search
        |
        v
Scheduled alert - Windows Brute Force Detection
        |
        v
Triggered Alerts / analyst review
```

## Detection: repeated Windows failed logons

**Event ID:** `4625` — An account failed to log on.

**Detection logic:** Extract the source IP and target username, group events by source and account, and return groups with five or more failures.

See [`detections/windows_failed_logon_bruteforce.spl`](detections/windows_failed_logon_bruteforce.spl).

## Example configuration

Example Universal Forwarder configuration files are provided in [`configs/`](configs/). Replace the example server address with your own Splunk server IP before using them.

- [`inputs.conf.example`](configs/inputs.conf.example)
- [`outputs.conf.example`](configs/outputs.conf.example)

## Evidence

| Screenshot | What it demonstrates |
|---|---|
| `screenshots/failed-logon-detection-spl.png` | SPL search and five matching failed-logon events (private values redacted) |
| `screenshots/triggered-alert.png` | Triggered Splunk alert |

## Validation searches

Check Windows Security event ingestion:

```spl
index=main sourcetype="XmlWinEventLog:Security"
| stats count by host
```

Search for failed logons:

```spl
index=main sourcetype="XmlWinEventLog:Security" "<EventID>4625</EventID>"
```

## Alert configuration summary

- Detection threshold: 5 or more failed logons
- Search interval: every minute
- Search window: previous 5 minutes
- Severity: High
- Trigger condition: number of results greater than 0
- Throttling: 5 minutes
- Suppression fields: `SourceIP`, `TargetUserName`

Exact schedules and field availability should be verified in the local Splunk instance before reusing the configuration.

## Scope and future improvements

The current evidence focuses on Windows log ingestion and failed-logon detection. Additional scenarios such as successful-login correlation, account changes, privilege changes, PowerShell logging, Sysmon, service creation, Defender detections, and phishing triage are potential future enhancements; they are not claimed here as completed investigations.


## Disclaimer

This repository is for educational and defensive security monitoring purposes.
