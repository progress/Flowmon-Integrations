# Flowmon ADS/IDS Integration with ProLion CryptoSpike

Integrating Flowmon's network anomaly detection capabilities with ProLion CryptoSpike enables early warning, detection, and automated remediation of security threats — specifically by blocking the Windows user account associated with a suspicious source IP directly on the storage platform.

The original version using credentials is described.

[Integration guide](/ProLion/ADS-ProLion-CryptoSpike-API-integration.pdf)

[Integration script](/ProLion/cryptospike-block-user.py)

Details below are for cryptospike-block-user-v2.py script. It's recommended to use this version as it allows more features and has token based authentication for the queries.


---

## How It Works

When Flowmon ADS or IDS detects an anomaly, it passes a tab-separated event to the script via stdin. The script then:

1. Queries CryptoSpike for file activity from the event's source IP in the last 30 minutes
2. If a single unique Windows user is identified → **blocks that user** on CryptoSpike
3. If no file activity match is found (ADS only) → falls back to searching by the **User Identity** name provided by Flowmon
4. Writes a detailed audit comment to the blocked user record, including the event ID, signature/type, source, targets and data feed

IDS events follow the same IP-based lookup but have no username fallback.

---

## Prerequisites

- Flowmon ADS deployed and configured with at least one data feed
- ProLion CryptoSpike reachable from the Flowmon appliance
- A CryptoSpike **application API token** with `StorageUser MODIFY`, `StorageUser READ`, and `FileActivity READ` permissions
- Python 3 with the `requests` library (pre-installed on Flowmon appliances)

---

## Deployment

Configuration of the CryptoSpike is covered by article published at the [prolion.com](https://help.service.prolion.com/servicedesk/customer/portal/11/article/3018260636) where you need to be logged in. It currently says:

### Creating a token
1. Settings → System → API Tokens → New Token.
2. Pick the user the token will act as. The token inherits whatever permissions that user has — pick the lowest-privilege user that can do the job.
3. Add a label that identifies the consumer (FlowmonADS). Future you will thank past you.
4. Click Generate. The product shows the token value once. Copy it now. After you close the dialog, the value is unrecoverable; lose it and you create a new one.

### 1. Copy the script to the Flowmon appliance

```bash
scp cryptospike-block-user-v2.py flowmon@<flowmon-ip>:/data/components/apps/
```

### 2. Store the API token

Create a token file readable only by the `flowmon` user:

```bash
echo "xapp-eyJ..." > /home/flowmon/cryptospike-token
chmod 600 /home/flowmon/cryptospike-token
```

The script reads this file automatically. No credentials need to appear in the Flowmon UI or command line.

> **Token location:** `/home/flowmon/cryptospike-token` (default, override with `--token-file`)

### 3. Verify connectivity

```bash
python3 /data/components/apps/cryptospike-block-user-v2.py --help
```

---

## Configuring Flowmon ADS

### Step 1 — Create a Filter

Limit detections to the networks you want to monitor (e.g. hosts where file servers or backup targets reside).

1. Go to **ADS → Settings → Processing → Filters**
2. Click **+ NEW FILTER**
3. Select **Atomic**, add the relevant network ranges under Parameters
4. Click **SAVE**

### Step 2 — Create a Perspective

Perspectives define which traffic patterns trigger detections and at what priority.

1. Go to **ADS → Settings → Processing → Perspectives**
2. Click **+ NEW PERSPECTIVE**
3. Assign the Filter and Data feed created above
4. Add detection methods per priority level (see [Recommended Methods](#recommended-detection-methods))
5. Click **SAVE**

### Step 3 — Register the Script

1. Go to **ADS → Settings → System Settings → Custom scripts**
2. Click **+ NEW CUSTOM SCRIPT**
3. Provide a name (e.g. `CryptoSpike Block User`)
4. Upload `cryptospike-block-user-v2.py`
5. Click **SAVE**

### Step 4 — Create a Custom Script Action

1. Go to **ADS → Settings → Processing → Custom scripts**
2. Click **+ NEW CUSTOM SCRIPT ACTION**
3. Provide a name and select the Perspective from Step 2
4. Set **Parameters** (only `-i` is required if the token file is in the default location):
   ```
   -i <cryptospike-ip>
   ```
5. Tick **Active** and set the minimum priority threshold
6. Click **SAVE**

---

## Configuring Flowmon IDS

IDS custom scripts are triggered manually from an event detail page or via automation rules.

Use the same script and parameters as for ADS. The script auto-detects the event type by field count (14 fields = IDS, 15/17 fields = ADS).

---

## Script Reference

### Usage

```bash
echo "<tab-separated event>" | python3 cryptospike-block-user-v2.py [options]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--ip` | `10.100.24.13` | CryptoSpike IP address or hostname |
| `-t`, `--token` | — | API token (avoid — visible in process list) |
| `--token-file` | `/home/flowmon/cryptospike-token` | Path to file containing the API token |

### Token resolution order

1. `--token` CLI argument
2. `CRYPTOSPIKE_API_TOKEN` environment variable
3. File at `--token-file` path

### Logging

All activity is logged to:
```
/data/components/apps/log/cryptospike-api.log
```

---

## Recommended Detection Methods

The following methods are a good starting point. Adjust to match your network environment and validate with test triggers before enabling blocking in production.

| Method | Description |
|--------|-------------|
| `SCANS` | Port and network scanning |
| `RANDOMDOMAIN` | DGA / random domain queries |
| `BPATTERNS` | Behaviour patterns |
| `DICTATTACK` | Dictionary-based attacks |
| `SSHDICT` | SSH brute force |
| `RDPDICT` | RDP brute force |
| `BLACKLIST` | BotnetActivities, MalwareDomains, BotnetDomains |

> Progress Flowmon engineers are available to assist with method selection. Always test triggers before enabling automated blocking in production.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `401 Token invalid` | Token expired or incorrectly copied — regenerate in CryptoSpike |
| `No file activity found for IP` | The source IP had no file activity on the NAS in the last 30 min — no block taken |
| `Multiple user IDs found for IP` | Two different users accessed the NAS from the same IP — ambiguous, no block taken by design |
| `No UID found for username` | User Identity not enrolled in CryptoSpike |
| `Permission denied reading token file` | Token file not owned by `flowmon` or missing `chmod 600` |
