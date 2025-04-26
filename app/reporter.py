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
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"reports/incident-report-{timestamp}.md"
    
    # Build the report content
    report = [
        "# ThreatSage Incident Report",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Alert:** {alert_text}",
        f"**Threat Score:** {analysis['threat_score']}/100",
        "",
        "## Extracted Entities",
        "",
    ]
    
    # Add extracted entities
    if entities["ips"]:
        report.append(f"**IP Addresses:** {', '.join(entities['ips'])}")
    if entities["usernames"]:
        report.append(f"**Usernames:** {', '.join(entities['usernames'])}")
    if entities["actions"]:
        report.append(f"**Actions:** {', '.join(entities['actions'])}")
    if entities["times"]:
        report.append(f"**Timestamps:** {', '.join(entities['times'])}")
    
    # Add IP intelligence for each IP
    report.append("")
    report.append("## IP Intelligence")
    report.append("")
    
    for ip, data in ip_data.items():
        report.append(f"### {ip}")
        report.append("")
        
        if "Error" in data:
            report.append(f"**Error:** {data['Error']}")
        else:
            # Add intelligence data in a table format
            report.append("| Attribute | Value |")
            report.append("| --- | --- |")
            
            for key, value in data.items():
                if key != "Error":
                    report.append(f"| {key} | {value} |")
        
        report.append("")
    
    # Add analysis and recommendation
    report.append("## Analysis & Recommendation")
    report.append("")
    report.append(analysis["recommendation"])
    report.append("")
    
    # Add MITRE ATT&CK mapping (simplified)
    report.append("## Potential MITRE ATT&CK Tactics")
    report.append("")
    
    # Simple heuristic mapping based on entities and data
    tactics = []
    
    # Check for potential tactics based on the data
    found_proxy = any(data.get("Is Proxy", False) for ip, data in ip_data.items() if "Error" not in data)
    suspicious_rep = any(data.get("Reputation") == "Suspicious" for ip, data in ip_data.items() if "Error" not in data)
    
    if found_proxy:
        tactics.append("- **Command and Control (TA0011):** Use of proxy services to hide true source")
    
    if "login" in [a.lower() for a in entities.get("actions", [])]:
        tactics.append("- **Initial Access (TA0001):** Potential unauthorized login attempts")
        
    if suspicious_rep:
        tactics.append("- **Impact (TA0040):** Activity from known-malicious infrastructure")
    
    # Add default if none found
    if not tactics:
        tactics.append("- No clear MITRE ATT&CK tactics identified with current data")
        
    report.extend(tactics)
    
    # Add footer
    report.append("")
    report.append("---")
    report.append("*Report generated automatically by ThreatSage*")
    
    # Write the report to file
    with open(filename, "w") as f:
        f.write("\n".join(report))
        
    return filename