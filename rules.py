"""Rule / signature engine. Each rule is a vectorised test over the feature table."""
from dataclasses import dataclass
from typing import Callable

from .config import ADMIN_PORTS, AUTH_PORTS, BAD_PORTS, CLEARTEXT_PORTS


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    kind: str          # signature | threshold | behavioural
    points: int        # risk points added when the rule fires
    mitre: str         # MITRE ATT&CK technique ID (for context)
    description: str
    mask: Callable     # DataFrame -> boolean Series


def _ext_out(d):
    return (d.src_internal == 1) & (d.dst_internal == 0)


RULES = [
    Rule("R001", "Known backdoor / botnet port", "signature", 40, "T1571",
         "Connection to a port commonly used by backdoors or IRC botnets.",
         lambda d: d.dst_port.isin(BAD_PORTS)),
    Rule("R002", "Cleartext protocol (Telnet/FTP)", "signature", 8, "T1021",
         "Credentials and data travel unencrypted.",
         lambda d: d.dst_port.isin(CLEARTEXT_PORTS)),
    Rule("R003", "SYN-only probe rejected with reset", "signature", 5, "T1046",
         "Tiny half-open connection answered with RST: typical of port probing.",
         lambda d: (d.syn_count >= 1) & (d.packets <= 3) & (d.rst_count >= 1)),
    Rule("R004", "Repeated failed authentication", "signature", 25, "T1110",
         "Five or more failed logins inside one connection.",
         lambda d: d.failed_auth >= 5),
    Rule("R005", "Large outbound transfer to external host", "signature", 25, "T1041",
         "5 MB or more sent from inside to outside: possible data exfiltration.",
         lambda d: (d.bytes_out >= 5_000_000) & _ext_out(d)),
    Rule("R006", "Extreme packet rate", "signature", 30, "T1498",
         "1000+ packets per second in one flow.",
         lambda d: d.pps >= 1000),
    Rule("R007", "External source to admin service", "signature", 15, "T1021",
         "Internet host talking to SSH/RDP/SMB/DB/VNC on an internal server.",
         lambda d: (d.src_internal == 0) & (d.dst_internal == 1) & d.dst_port.isin(ADMIN_PORTS)),
    Rule("R008", "Off-hours large outbound transfer", "signature", 10, "T1041",
         "1 MB+ leaving the network between 00:00 and 05:00 UTC.",
         lambda d: (d.off_hours == 1) & (d.bytes_out >= 1_000_000) & _ext_out(d)),
    Rule("W001", "Port scan (many ports in 60 s)", "threshold", 50, "T1046",
         "One source touched 15+ distinct destination ports within a minute.",
         lambda d: d.src_dports_w >= 15),
    Rule("W002", "Brute force (repeated logins)", "threshold", 40, "T1110",
         "8+ connections from one source to the same login service within a minute.",
         lambda d: (d.pair_flows_w >= 8) & d.dst_port.isin(AUTH_PORTS)),
    Rule("W003", "SYN / connection flood", "threshold", 45, "T1498",
         "200+ SYN packets or 150+ connections from one source within a minute.",
         lambda d: (d.src_syn_w >= 200) | (d.src_flows_w >= 150)),
    Rule("W004", "Periodic beaconing to external host", "behavioural", 25, "T1071",
         "Small, evenly spaced connections from an internal host to one external address.",
         lambda d: (d.beacon_cv < 0.15) & (d.beacon_iv >= 5) & (d.beacon_iv <= 3600)
                   & (d.bytes_out < 5000) & _ext_out(d)),
]
RULE_INDEX = {r.id: r for r in RULES}
