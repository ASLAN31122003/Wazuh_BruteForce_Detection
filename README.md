# SOC Lab: Web Application Brute-Force Detection, Active Response, and Real-Time Alerting with Wazuh

This lab demonstrates how to build a small **Security Operations Center (SOC) monitoring workflow** using Wazuh.

The lab covers:

* Flask web application authentication logging
* Wazuh agent log collection
* Custom Wazuh decoders
* Custom detection rules
* Brute-force detection through event correlation
* MITRE ATT&CK mapping
* Automated firewall response
* Discord webhook alerting
* Verification and troubleshooting

---

## Environment Architecture

| Component           | Details                              |
| ------------------- | ------------------------------------ |
| **Wazuh Manager**   | `ip-wazuh` (`wazuh-server`)     |
| **Target Agent**    | `ip-agent` (`kalibrute`)          |
| **Agent ID**        | `00X`                                |
| **Web Application** | Flask                                |
| **Application URL** | `http://ip:5000/login`     |
| **Application Log** | `/PATH/webapp/app.log` |

### Architecture

```text
                 ┌──────────────────────────┐
                 │     Attacker / Tester    │
                 │                          │
                 │  curl / Hydra            │
                 └────────────┬─────────────┘
                              │
                              │ HTTP POST
                              ▼
                 ┌──────────────────────────┐
                 │     Flask Web App        │
                 │         ip:5000          │
                 │                          │
                 │      /login              │
                 └────────────┬─────────────┘
                              │
                              │ FAILED_LOGIN
                              ▼
                 ┌──────────────────────────┐
                 │       app.log            │
                 │                          │
                 │ /PATH/webapp/app.log     │
                 │                          │
                 └────────────┬─────────────┘
                              │
                              │ Wazuh Agent
                              ▼
                 ┌──────────────────────────┐
                 │     Wazuh Manager        │
                 │            ip            │
                 │                          │
                 │ Decoder → Rule → Alert   │
                 └────────────┬─────────────┘
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
       ┌─────────────────┐        ┌─────────────────┐
       │ Active Response │        │ Discord Webhook │
       │ Firewall Block  │        │ Real-time Alert │
       └─────────────────┘        └─────────────────┘
```

---

# Phase 1: Python Web Application Setup

## 1.1 Create the Project Directory

Run these commands on the Kali agent:

```bash
mkdir -p /home/kali/Projects/webapp
cd /home/kali/Projects/webapp
```

---

## 1.2 Create the Flask Application

Create `/home/kali/Projects/webapp/app.py`:

```bash
import logging
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Set up logger with forced flushing
logger = logging.getLogger('webapp')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('/home/kali/Projects/webapp/app.log')
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [webapp] %(message)s'))
logger.addHandler(handler)

HTML_FORM = """
<!DOCTYPE html>
<html>
<head><title>Web App Login</title></head>
<body style="font-family: Arial; margin: 50px;">
    <h2>Login Page</h2>
    <form method="POST" action="/login">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

@app.route('/', methods=['GET'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(HTML_FORM)

    username = request.form.get('username') or ''
    password = request.form.get('password') or ''

    if username == 'admin' and password == 'Secret123':
        logger.info(f"SUCCESSFUL_LOGIN user='{username}' ip='{request.remote_addr}'")
        return "<h3>Login Successful!</h3>", 200
    else:
        logger.warning(f"FAILED_LOGIN user='{username}' ip='{request.remote_addr}'")
        return "<h3>Invalid Credentials</h3>", 401

if __name__ == '__main__':
    app.run(host='ip', port=5000)
```

---

## 1.3 Install Flask

```bash
pip install flask
```

If your system uses a Python virtual environment, it is preferable to install Flask inside the virtual environment.

---

## 1.4 Launch the Application

```bash
python3 /home/kali/Projects/webapp/app.py &
```

Check that the application is listening:

```bash
ss -lntp | grep 5000
```

Test the login endpoint:

```bash
curl -i http://ip:5000/login
```

---

# Phase 2: Wazuh Agent Log Collection

The Flask application writes failed authentication events to:

```text
/home/kali/Projects/webapp/app.log
```

The Wazuh agent must be configured to monitor this file.

```bash
sudo chmod +x /PATH #/home/kali /home/kali/Projects /home/kali/Projects/webapp
sudo chmod 644 /home/kali/Projects/webapp/app.log
```

## 2.1 Configure the Agent

On the Kali Wazuh agent:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add the following configuration:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/PATH/webapp/app.log</location>
</localfile>
```

> **Note:** If `/var/ossec/etc/ossec.conf` already contains an `<ossec_config>` root element, add only the `<localfile>` block inside the existing configuration. Do not create a second root element.

---

## 2.2 Restart the Wazuh Agent

```bash
sudo systemctl restart wazuh-agent
```

Check the service:

```bash
sudo systemctl status wazuh-agent
```

---

# Phase 3: Custom Decoder and Detection Rules

The Wazuh Manager needs to understand the custom Flask log format.

---

## 3.1 Create the Custom Decoder

On the Wazuh Manager:

```bash
sudo nano /var/ossec/etc/decoders/local_decoder.xml
```

Add:

```xml
<decoder name="webapp_login">
  <prematch>FAILED_LOGIN</prematch>
</decoder>

<decoder name="webapp_login_fields">
  <parent>webapp_login</parent>
  <regex>user='(\S+)' ip='(\S+)'</regex>
  <order>dstuser, srcip</order>
</decoder>

```

The decoder extracts:

| Field     | Meaning                                |
| --------- | -------------------------------------- |
| `dstuser` | Username targeted by the login attempt |
| `srcip`   | Source IP address                      |

---

# Phase 4: Custom Detection Rules

Create the detection rules on the Wazuh Manager:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add:

```xml
cat /var/ossec/etc/rules/local_rules.xml
<!-- Local rules -->
<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example (Commented out to prevent Rule 100001 duplication) -->
<!--
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
-->

<group name="webapp,">
  <!-- Rule 100001: Individual Login Failure -->
  <rule id="100001" level="5">
    <decoded_as>webapp_login</decoded_as>
    <description>Web application failed login attempt for user $(dstuser).</description>
  </rule>

  <!-- Rule 100002: Brute-Force Threshold Correlation -->
  <rule id="100002" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100001</if_matched_sid>
    <same_source_ip />
    <description>Possible web application brute force attack detected.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

---

## Detection Logic

The rules implement two stages.

### Rule 100001 — Individual Failure

Every failed login produces a level 5 event:

```text
FAILED_LOGIN
       │
       ▼
Rule 100001
       │
       ▼
Level 5 Alert
```

### Rule 100002 — Brute-Force Correlation

The second rule looks for repeated events from the same source IP.

```text
8 failed logins
      │
      │ within 120 seconds
      ▼
Same Source IP
      │
      ▼
Rule 100002
      │
      ▼
Level 10 Alert
      │
      ├───────────────┐
      ▼               ▼
Active Response    Discord Alert
```

The detection threshold is:

```text
Frequency: 8 events
Timeframe: 120 seconds
Source: Same IP
```

The rule is mapped to:

```text
MITRE ATT&CK T1110
```

which represents **Brute Force**.

---

# Phase 5: Validate the Decoder and Rules

Use Wazuh's log testing utility on the manager:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a sample event:

```text
2026-09-16 03:39:09,773 WARNING [webapp] FAILED_LOGIN user='admin' ip='172.16.88.20'
```

The log should be decoded as:

```text
webapp_login
```

and the extracted fields should include values similar to:

```text
dstuser = admin
srcip   = 172.16.88.20
```

The event should subsequently match the corresponding detection rule.

---

# Phase 6: Active Response and Webhook Integration

This phase connects the detection rule to two response mechanisms:

1. Firewall blocking
2. Discord notification

---

## 6.1 Configure Active Response

On the Wazuh Manager, edit:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add the active response configuration inside the existing `<ossec_config>` element:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>60</timeout>
</active-response>
```

This means that when rule `100002` triggers, Wazuh invokes the `firewall-drop` active response.

The configured timeout is:

```text
60 seconds
```

---

# Phase 7: Discord Alert Integration

Configure the webhook integration in the Wazuh Manager.

> **Security:** Never commit a real Discord webhook URL to GitHub. Store it securely and use a placeholder in public documentation.

Example:

```xml
<integration>
  <name>custom-discord</name>
  <hook_url>https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN</hook_url>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

### Recommended GitHub configuration

For a public repository, use:

```xml
<hook_url>YOUR_DISCORD_WEBHOOK_URL</hook_url>
```

and provide the real value through a secure local configuration or secret-management mechanism.

---

## Important: Rotate Exposed Webhooks

If the webhook from the original lab configuration is still active and was committed anywhere publicly, **delete/rotate it in Discord and generate a new webhook**.

A Discord webhook URL functions as a credential for sending messages to that webhook.

---

# Phase 8: Restart Wazuh Manager

After changing the configuration:

```bash
sudo systemctl restart wazuh-manager
```

Check the service:

```bash
sudo systemctl status wazuh-manager
```

If the service fails to start, inspect:

```bash
sudo journalctl -u wazuh-manager -n 50 --no-pager
```

and:

```bash
sudo tail -n 50 /var/ossec/logs/ossec.log
```

---

# Phase 9: Brute-Force Simulation

The following tests are intended for the isolated lab environment.

## Option A: Bash/Curl Simulation

Run from the test/attacker system:

```bash
for i in {1..12}; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://ip:5000/login -d "username=admin&password=wrongpassword"
  sleep 0.2
done

```

Expected HTTP response:

```text
401
```

The application should generate multiple log entries:

```text
FAILED_LOGIN user='admin' ip='ip'
```

Once the configured threshold is reached, Wazuh should generate the brute-force detection event.

---

# Option B: Hydra Form Test

For an authorized lab environment, Hydra can also be used to test the login form:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  ip http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials" \
  -t 4 -V
```

### Parameters

| Parameter               | Purpose                    |
| ----------------------- | -------------------------- |
| `-l admin`              | Username to test           |
| `-P`                    | Password wordlist          |
| `http-post-form`        | HTTP POST form module      |
| `/login`                | Login endpoint             |
| `^USER^`                | Hydra username placeholder |
| `^PASS^`                | Hydra password placeholder |
| `F=Invalid credentials` | Failure condition          |
| `-t 4`                  | Four concurrent tasks      |
| `-V`                    | Verbose output             |

Use this only against systems you own or are explicitly authorized to test.

---

# Phase 10: Verification

After running the simulation, verify that each component of the SOC pipeline worked correctly.

---

## 10.1 Check Wazuh Detection

Run on the Wazuh Manager:

```bash
sudo grep "100002" /var/ossec/logs/alerts/alerts.log | tail -n 10
```

You should see entries associated with rule:

```text
100002
```

---

## 10.2 Check Active Response

Run on the Kali agent:

```bash
sudo tail -n 10 /var/ossec/logs/active-responses.log
```

Look for execution of the firewall response.

---

## 10.3 Inspect Firewall Rules

On the Kali agent:

```bash
sudo iptables -L INPUT -n -v | grep ip
```

Depending on the firewall configuration and Wazuh version, the exact rule representation may differ.

---

## 10.4 Check Discord Integration

On the Wazuh Manager:

```bash
sudo grep -i "discord" /var/ossec/logs/ossec.log | tail -n 10
```

This can help determine whether the integration attempted to send the alert.

---

# Complete SOC Detection Flow

The complete workflow can be summarized as:

```text
                    ┌─────────────────┐
                    │ Login Attempts  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Flask App     │
                    │    /login       │
                    └────────┬────────┘
                             │
                       Failed Login
                             │
                             ▼
                    ┌─────────────────┐
                    │    app.log      │
                    └────────┬────────┘
                             │
                       Wazuh Agent
                             │
                             ▼
                    ┌─────────────────┐
                    │ Custom Decoder  │
                    │ webapp_login    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    Rule 100001  │
                    │ Single Failure  │
                    └────────┬────────┘
                             │
                       Repeated Events
                             │
                             ▼
                    ┌─────────────────┐
                    │    Rule 100002  │
                    │ 8 / 120 sec     │
                    └────────┬────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
       ┌─────────────────┐       ┌─────────────────┐
       │ Active Response │       │ Discord Webhook │
       │ Firewall Drop   │       │ SOC Notification│
       └─────────────────┘       └─────────────────┘
```

---

# Configuration Summary

| Component             | Configuration                        |
| --------------------- | ------------------------------------ |
| Web application       | Flask                                |
| Application port      | `5000`                               |
| Application log       | `/home/kali/Projects/webapp/app.log` |
| Wazuh agent           | `kalibrute`                          |
| Agent ID              | `002`                                |
| Decoder               | `webapp_login`                       |
| Single-failure rule   | `100001`                             |
| Brute-force rule      | `100002`                             |
| Brute-force threshold | `8 events / 120 seconds`             |
| Detection level       | `10`                                 |
| MITRE ATT&CK          | `T1110`                              |
| Active response       | `firewall-drop`                      |
| Firewall timeout      | `60 seconds`                         |
| Alert format          | JSON                                 |
| Notification          | Discord webhook                      |

---

# Troubleshooting

## Flask Application Not Running

Check:

```bash
ps aux | grep app.py
```

Check port:

```bash
ss -lntp | grep 5000
```

Run manually:

```bash
python3 /home/kali/Projects/webapp/app.py
```

---

## No Events in Wazuh

Check the application log:

```bash
tail -f /home/kali/Projects/webapp/app.log
```

Check the Wazuh agent:

```bash
sudo systemctl status wazuh-agent
```

Check agent logs:

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

---

## Decoder Not Matching

Run:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Test with:

```text
2026-09-16 03:39:09,773 WARNING [webapp] FAILED_LOGIN user='admin' ip='ip'
```

Verify that the decoder identifies:

```text
webapp_login
```

---

## Rule 100002 Not Triggering

Verify that multiple events are being generated:

```bash
tail -n 20 /home/kali/Projects/webapp/app.log
```

Check the threshold:

```text
8 events
within 120 seconds
from the same source IP
```

Also verify that Rule `100001` is matching before troubleshooting Rule `100002`.

---

## Manager Configuration Problems

Check:

```bash
sudo systemctl status wazuh-manager
```

Then:

```bash
sudo journalctl -u wazuh-manager -n 50 --no-pager
```

and:

```bash
sudo tail -n 50 /var/ossec/logs/ossec.log
```

---

# Security Considerations

This lab intentionally demonstrates brute-force detection and automated response in a controlled environment.

For production deployments:

* Never expose webhook URLs in Git repositories.
* Rotate credentials that have been exposed.
* Store secrets outside configuration repositories.
* Restrict Wazuh manager access.
* Use TLS for communication where applicable.
* Tune detection thresholds to reduce false positives.
* Test active-response rules before deploying them broadly.
* Maintain backups of Wazuh configuration files.
* Monitor the active-response logs.
* Restrict testing tools such as Hydra to systems for which you have authorization.

---

# Learning Objectives

After completing this lab, you should understand how to:

1. Generate structured authentication logs from a web application.
2. Configure a Wazuh agent to collect application logs.
3. Create a custom Wazuh decoder.
4. Create custom Wazuh detection rules.
5. Correlate repeated authentication failures.
6. Map detections to MITRE ATT&CK.
7. Trigger an automated firewall response.
8. Send security alerts through a webhook.
9. Validate and troubleshoot the complete SOC pipeline.

---

# Final Result

The completed lab provides an end-to-end security monitoring pipeline:

```text
Web Login
    ↓
Authentication Failure
    ↓
Application Log
    ↓
Wazuh Agent
    ↓
Custom Decoder
    ↓
Detection Rule
    ↓
Brute-Force Correlation
    ↓
┌───────────────────┬───────────────────┐
│                   │                   │
▼                   ▼                   │
Firewall Block      Discord Alert       │
│                   │                   │
└───────────────────┴───────────────────┘
                    │
                    ▼
              SOC Visibility
```

This demonstrates the basic SOC workflow of **log collection → detection → correlation → automated response → alerting**.
