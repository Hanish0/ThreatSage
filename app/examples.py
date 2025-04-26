# app/examples.py
import sys
import os
sys.path.append(os.path.abspath("."))
from app.enrichment import ThreatIntelligence
from app.agent import IncidentResponder
from app.extractor import EntityExtractor
from app.main import print_banner, print_info, print_warning, print_success, print_error

def demo_ip_enrichment():
    """Demo the IP enrichment functionality"""
    print_info("\n[*] Demonstrating IP Enrichment")
    test_ip = "185.107.56.21"
    print(f"  - Enriching {test_ip}...")
    
    threat_intel = ThreatIntelligence()
    enriched_data = threat_intel.enrich_ip(test_ip)
    
    if "Error" in enriched_data:
        print_error(f"  ✘ Error: {enriched_data['Error']}")
    else:
        print_success("  ✓ Enrichment successful")
        for key, value in enriched_data.items():
            if key == "Reputation" and value == "Suspicious":
                print_warning(f"    {key}: {value}")
            else:
                print(f"    {key}: {value}")
    
    return enriched_data

def demo_entity_extraction():
    """Demo the entity extraction functionality"""
    print_info("\n[*] Demonstrating Entity Extraction")
    
    test_alerts = [
        "Multiple failed SSH logins from IP 45.13.22.98 for root account at 03:44 AM",
        "Admin user john.doe logged in from unusual location IP 185.107.56.21",
        "Firewall blocked connection attempt from 192.168.1.5 to internal server",
    ]
    
    extractor = EntityExtractor()
    
    for i, alert in enumerate(test_alerts):
        print(f"\n  - Alert {i+1}: {alert}")
        entities = extractor.extract_all(alert)
        print(f"    IPs: {', '.join(entities['ips']) if entities['ips'] else 'None'}")
        print(f"    Usernames: {', '.join(entities['usernames']) if entities['usernames'] else 'None'}")
        print(f"    Actions: {', '.join(entities['actions']) if entities['actions'] else 'None'}")
        print(f"    Times: {', '.join(entities['times']) if entities['times'] else 'None'}")
    
    return extractor

def demo_full_analysis():
    """Demo the full ThreatSage analysis workflow"""
    print_info("\n[*] Demonstrating Full Analysis Workflow")
    
    # Test alert with suspicious IP
    test_alert = "Admin login from 185.107.56.21 at 3:44 AM (unusual location)."
    print(f"  - Alert: {test_alert}")
    
    # Step 1: Extract entities
    extractor = EntityExtractor()
    entities = extractor.extract_all(test_alert)
    
    print_info("  - Extracted entities:")
    print(f"    IPs: {', '.join(entities['ips'])}")
    print(f"    Actions: {', '.join(entities['actions'])}")
    
    # Step 2: Enrich IP data
    threat_intel = ThreatIntelligence()
    ip_data = {}
    
    if entities['ips']:
        ip = entities['ips'][0]
        print_info(f"  - Enriching IP: {ip}")
        ip_data[ip] = threat_intel.enrich_ip(ip)
        
        for key, value in ip_data[ip].items():
            if key == "Reputation" and value == "Suspicious":
                print_warning(f"    {key}: {value}")
            else:
                print(f"    {key}: {value}")
    
    # Step 3: Agent reasoning
    print_info("  - Performing threat analysis")
    responder = IncidentResponder()
    analysis = responder.reason(ip_data[entities['ips'][0]], raw_alert=test_alert)
    
    # Display results
    print_info("  - Analysis Results:")
    print(f"    Threat Score: {analysis['threat_score']}/100")
    print(f"    Recommendation: {analysis['recommendation']}")
    
    return {
        "entities": entities,
        "ip_data": ip_data,
        "analysis": analysis
    }

def run_all_demos():
    """Run all demonstration functions"""
    print_banner()
    demo_ip_enrichment()
    demo_entity_extraction()
    demo_full_analysis()
    print_info("\n[*] All demonstrations completed")

if __name__ == "__main__":
    run_all_demos()