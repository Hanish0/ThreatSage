import os
import time
from datetime import datetime

def generate_report(entities, ip_data, analysis, alert_text):
    """
    Generate a detailed markdown report of the security incident
    
    Args:
        entities: Dictionary of extracted entities
        ip_data: Dictionary of IP intelligence data
        analysis: Dictionary with threat score and recommendation
        alert_text: Original alert text
        
    Returns:
        Filename of the generated report
    """
    os.makedirs("reports", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"reports/incident-report-{timestamp}.md"
    
    report = [
        "# ThreatSage Incident Report",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Alert:** {alert_text}",
        f"**Threat Score:** {analysis['threat_score']}/100",
        "",
        "## Extracted Entities",
        "",
    ]
    
    if entities["ips"]:
        report.append(f"**IP Addresses:** {', '.join(entities['ips'])}")
    if entities["usernames"]:
        report.append(f"**Usernames:** {', '.join(entities['usernames'])}")
    if entities["actions"]:
        report.append(f"**Actions:** {', '.join(entities['actions'])}")
    if entities["times"]:
        report.append(f"**Timestamps:** {', '.join(entities['times'])}")
    
    report.append("")
    report.append("## IP Intelligence")
    report.append("")
    
    for ip, data in ip_data.items():
        report.append(f"### {ip}")
        report.append("")
        
        if "Error" in data:
            report.append(f"**Error:** {data['Error']}")
        else:
            report.append("| Attribute | Value |")
            report.append("| --- | --- |")
            
            for key, value in data.items():
                if key != "Error":
                    report.append(f"| {key} | {value} |")
        
        report.append("")
    
    report.append("## Analysis & Recommendation")
    report.append("")
    report.append(analysis["recommendation"])
    report.append("")
    
    report.append("## Potential MITRE ATT&CK Tactics")
    report.append("")
    
    tactics = []
    
    found_proxy = any(data.get("Is Proxy", False) for ip, data in ip_data.items() if "Error" not in data)
    suspicious_rep = any(data.get("Reputation") == "Suspicious" for ip, data in ip_data.items() if "Error" not in data)
    
    if found_proxy:
        tactics.append("- **Command and Control (TA0011):** Use of proxy services to hide true source")
    
    if "login" in [a.lower() for a in entities.get("actions", [])]:
        tactics.append("- **Initial Access (TA0001):** Potential unauthorized login attempts")
        
    if suspicious_rep:
        tactics.append("- **Impact (TA0040):** Activity from known-malicious infrastructure")
    
    if not tactics:
        tactics.append("- No clear MITRE ATT&CK tactics identified with current data")
        
    report.extend(tactics)
    
    report.append("")
    report.append("---")
    report.append("*Report generated automatically by ThreatSage*")
    
    with open(filename, "w") as f:
        f.write("\n".join(report))
        
    return filename