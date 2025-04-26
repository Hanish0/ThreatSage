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