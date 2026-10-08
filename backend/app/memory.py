import math
import time
from typing import Dict, List, Optional
from datetime import datetime, timezone

# ---------------------------------------------------------
# A. Episodic Memory (Active Chains with Time-Decay)
# Relevance = Sim(q, m) * exp(-lambda * (t_now - t_event))
# ---------------------------------------------------------
class EpisodicMemoryStore:
    def __init__(self, decay_rate: float = 0.001):
        self.decay_rate = decay_rate
        self.episodes: List[dict] = []

    def add_event(self, ip: str, endpoint: str, threat_type: str, severity: str, timestamp: Optional[float] = None):
        t_event = timestamp or time.time()
        episode = {
            "ip": ip,
            "endpoint": endpoint,
            "threat_type": threat_type,
            "severity": severity,
            "timestamp": t_event,
            "iso_time": datetime.fromtimestamp(t_event, tz=timezone.utc).isoformat()
        }
        self.episodes.append(episode)
        # Keep recent 200 episodes in active memory
        if len(self.episodes) > 200:
            self.episodes.pop(0)

    def get_active_chain_context(self, ip: str, current_time: Optional[float] = None) -> List[dict]:
        t_now = current_time or time.time()
        ip_episodes = [ep for ep in self.episodes if ep["ip"] == ip]
        
        scored_episodes = []
        for ep in ip_episodes:
            dt = max(0, t_now - ep["timestamp"])
            time_decay = math.exp(-self.decay_rate * dt)
            if time_decay > 0.1:  # Only include non-expired memory context
                ep_copy = ep.copy()
                ep_copy["relevance"] = round(time_decay, 3)
                scored_episodes.append(ep_copy)
                
        return sorted(scored_episodes, key=lambda x: x["timestamp"], reverse=True)

# ---------------------------------------------------------
# B. Semantic Memory (Vectorized MITRE TTP Knowledge)
# ---------------------------------------------------------
SEMANTIC_KNOWLEDGE_BASE = {
    "T1110": {
        "name": "Brute Force / Credential Stuffing",
        "description": "Adversaries attempt to gain access by testing multiple password combinations or stuffing stolen credentials against authentication endpoints like /api/v1/auth.",
        "vector_keywords": ["auth", "login", "401", "unauthorized", "password", "brute_force"]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application (SQLi / Injection)",
        "description": "Adversaries attempt to execute malicious database queries or bypass inputs via UNION SELECT or SQL injection payloads.",
        "vector_keywords": ["sqli", "union", "select", "database", "injection", "hex_encode"]
    },
    "T1595": {
        "name": "Active Scanning & Honeytoken Probing",
        "description": "Adversaries perform automated recon targeting decoy configuration traps like /.env, /wp-config.php, or /.git/config to extract secrets.",
        "vector_keywords": ["honeytoken", "env", "wp-config", "git", "secrets", "recon"]
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "description": "Adversaries encode payloads using Base64, Hex, or high-entropy parameters to evade simple string matching filters.",
        "vector_keywords": ["entropy", "obfuscated", "hex", "base64", "encoded"]
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "description": "Adversaries search for sensitive files, backup archives (.bak), or admin configuration portals.",
        "vector_keywords": ["discovery", "admin.bak", "config.json", "directory_search"]
    }
}

def get_semantic_threat_intel(mitre_id: str) -> dict:
    return SEMANTIC_KNOWLEDGE_BASE.get(mitre_id, {
        "name": "Unknown Technique",
        "description": "General anomaly pattern detected.",
        "vector_keywords": []
    })

# ---------------------------------------------------------
# C. Procedural Memory (Playbooks & Verified Remediation Rules)
# ---------------------------------------------------------
PROCEDURAL_PLAYBOOKS = {
    "T1110": {
        "nginx_block": "limit_req zone=login_limit burst=5 nodelay;",
        "firewall": "iptables -A INPUT -s {ip} -j DROP",
        "action": "Enforce strict IP rate limiting on /api/v1/auth and temporarily ban origin IP."
    },
    "T1190": {
        "nginx_block": "if ($args ~* \"(union|select|insert|concat)\") { return 403; }",
        "firewall": "iptables -A INPUT -s {ip} -j DROP",
        "action": "Sanitize query parameters and block request at WAF edge."
    },
    "T1595": {
        "nginx_block": "location ~ /\\.(env|git|htaccess) { deny all; return 404; }",
        "firewall": "iptables -A INPUT -s {ip} -j DROP",
        "action": "Blacklist origin IP instantly upon honeytoken tripwire activation."
    },
    "T1027": {
        "nginx_block": "if ($request_uri ~* \"(%27|%22|%20)\") { return 400; }",
        "firewall": "iptables -A INPUT -s {ip} -j DROP",
        "action": "Reject high-entropy obfuscated requests at reverse proxy layer."
    }
}

def get_procedural_playbook(mitre_id: str, ip: str) -> dict:
    playbook = PROCEDURAL_PLAYBOOKS.get(mitre_id, {
        "nginx_block": "deny all;",
        "firewall": f"iptables -A INPUT -s {ip} -j DROP",
        "action": "Block suspicious traffic."
    })
    return {
        "nginx_block": playbook["nginx_block"],
        "firewall": playbook["firewall"].format(ip=ip),
        "action": playbook["action"]
    }

# Single global instance of episodic memory
episodic_memory = EpisodicMemoryStore()
