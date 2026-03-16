PERSONA_RULES = {
    "Data Exfiltrator":       {"tools": ["curl", "wget", "netcat", "ftp"],       "weight": 3},
    "Network Intruder":       {"tools": ["nmap", "metasploit", "hydra", "sqlmap"],"weight": 3},
    "Insider Threat":         {"tools": ["bleachbit", "secure-delete", "tor"],    "weight": 2},
    "Wireless Attacker":      {"tools": ["aircrack-ng", "wireshark"],             "weight": 2},
    "Web Application Hacker": {"tools": ["burpsuite", "nikto", "sqlmap"],         "weight": 2},
}

def classify_persona(tools: list, paradoxes: list) -> tuple:
    """
    VENKAT'S MODULE
    Classifies attacker archetype from detected tool combinations.
    Returns (persona_name, confidence_score).
    """
    tool_names = [t["name"].lower() for t in tools]
    scores = {}

    for persona, rule in PERSONA_RULES.items():
        matches = sum(1 for t in rule["tools"] if t in tool_names)
        if matches > 0:
            scores[persona] = (matches / len(rule["tools"])) * rule["weight"]

    if paradoxes:
        scores["Insider Threat"] = scores.get("Insider Threat", 0) + 0.5

    if not scores:
        return "Unknown", 0.0

    best = max(scores, key=scores.get)
    raw = scores[best]
    confidence = round(min(raw / 3.0, 1.0), 2)
    return best, confidence