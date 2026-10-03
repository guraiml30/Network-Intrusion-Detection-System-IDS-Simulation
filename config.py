"""Central configuration: thresholds, port lists and recommendations. Tune detection here."""
import ipaddress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "ids_events.db"
DATASET_PATH = ROOT / "data" / "sample_flows.csv"
MODEL_PATH = ROOT / "models" / "ids_model.joblib"

REQUIRED_COLUMNS = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "duration",
                    "bytes_out", "bytes_in", "packets", "syn_count", "rst_count", "failed_auth"]
MAX_ROWS = 200_000
MAX_UPLOAD_BYTES = 30_000_000

# Only these ranges count as "internal". Documentation ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) are used for simulated EXTERNAL hosts.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

WINDOW_SECONDS = 60          # sliding window used by threshold rules
ALERT_GAP_SECONDS = 300      # flows further apart than this start a new alert

BAD_PORTS = {4444, 31337, 6667, 1337, 5555}
CLEARTEXT_PORTS = {21, 23}
ADMIN_PORTS = {22, 3389, 445, 3306, 5900}
AUTH_PORTS = {21, 22, 23, 3389, 5900}

NORMAL_MAX = 25        # risk < 25  -> NORMAL
INTRUSION_MIN = 50     # risk >= 50 -> POTENTIAL INTRUSION (25-49 SUSPICIOUS)
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_BANDS = [(25, "INFO"), (40, "LOW"), (60, "MEDIUM"), (80, "HIGH")]  # else CRITICAL
STATUSES = ["New", "Investigating", "Resolved", "False Positive"]

RECOMMENDATIONS = {
    "R001": "Isolate the internal host, inspect it for malware, and block the destination at the firewall.",
    "R002": "Replace Telnet/FTP with SSH/SFTP and rotate any credentials that crossed the wire.",
    "R003": "Review firewall logs for the source; rate-limit or block repeated half-open probes.",
    "R004": "Check the account for lockout, enforce MFA and rotate the password if any attempt succeeded.",
    "R005": "Confirm whether the transfer is authorised; if not, block the destination and preserve evidence.",
    "R006": "Apply rate limiting / SYN cookies and check the target service health.",
    "R007": "Restrict admin services to VPN or allow-listed addresses; never expose them to the internet.",
    "R008": "Verify with the data owner whether an out-of-hours transfer was expected.",
    "W001": "Block or rate-limit the scanning source and review which services it discovered.",
    "W002": "Block the source, enforce account lockout and MFA, and audit logins on the target.",
    "W003": "Enable flood protection at the edge, block offending sources and scale or shield the target.",
    "W004": "Investigate the internal host for malware; block the destination and review DNS/proxy logs.",
    "ANOM": "Statistically unusual traffic: compare with the host's normal behaviour before acting.",
}
