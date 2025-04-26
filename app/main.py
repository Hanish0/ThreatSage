import argparse
import sys
import time
from app.enrichment import ThreatIntelligence
from app.agent import IncidentResponder
from app.extractor import EntityExtractor
from app.reporter import generate_report

def print_banner():
    """Print ThreatSage banner"""
    banner = """
    
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗ █████╗  ██████╗ ███████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██╔════╝ ██╔════╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   ███████╗███████║██║  ███╗█████╗  
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ╚════██║██╔══██║██║   ██║██╔══╝  
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████║██║  ██║╚██████╔╝███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
                                                                                   
"""
    print(banner)

def colored_print(text, color_code):
    """Print text with ANSI color codes"""
    print(f"\033[{color_code}m{text}\033[0m")

def print_success(text):
    """Print success message in green"""
    colored_print(text, "32")

def print_warning(text):
    """Print warning message in yellow"""
    colored_print(text, "33")

def print_error(text):
    """Print error message in red"""
    colored_print(text, "31")

def print_info(text):
    """Print info message in blue"""
    colored_print(text, "36")

def process_text_alert(alert_text):
    """Process a free-text security alert"""
    print_info(f"[*] Processing alert: {alert_text}")
    
    # Step 1: Extract entities
    extractor = EntityExtractor()
    entities = extractor.extract_all(alert_text)
    
    print_info("\n[*] Extracted entities:")
    print(f"  IPs: {', '.join(entities['ips']) if entities['ips'] else 'None'}")
    print(f"  Usernames: {', '.join(entities['usernames']) if entities['usernames'] else 'None'}")
    print(f"  Actions: {', '.join(entities['actions']) if entities['actions'] else 'None'}")
    
    # Step 2: If we have IPs, enrich them
    threat_intel = ThreatIntelligence()
    ip_data = {}
    
    if entities['ips']:
        print_info(f"\n[*] Enriching {len(entities['ips'])} IPs...")
        for ip in entities['ips']:
            print(f"  - Processing {ip}...")
            ip_data[ip] = threat_intel.enrich_ip(ip)
            
            # Display enrichment results
            if "Error" in ip_data[ip]:
                print_error(f"    ✘ Error: {ip_data[ip]['Error']}")
            else:
                print_success(f"    ✓ {ip}: {ip_data[ip]['Country']} - {ip_data[ip]['Organization']}")
                if ip_data[ip].get('Reputation') == 'Suspicious':
                    print_warning(f"    ⚠ Reputation: {ip_data[ip]['Reputation']} ({ip_data[ip]['Confidence']} confidence)")
    else:
        print_warning("\n[!] No IP addresses found in the alert.")
        
    # Step 3: Analyze with agent
    print_info("\n[*] Analyzing threat data...")
    responder = IncidentResponder()
    
    # If we have enriched IPs, use the first one for analysis
    if entities['ips'] and ip_data[entities['ips'][0]]:
        analysis = responder.reason(ip_data[entities['ips'][0]], raw_alert=alert_text)
        
        # Display threat score with color coding
        score = analysis['threat_score']
        score_color = "31" if score > 70 else "33" if score > 30 else "32"
        print(f"  - Threat score: \033[{score_color}m{score}/100\033[0m")
        
        # Display recommendation
        print_info("\n[*] ThreatSage recommendation:")
        print("  " + analysis['recommendation'].replace('\n', '\n  '))
        
        # Generate report if score is high
        if score > 50:
            report_file = generate_report(entities, ip_data, analysis, alert_text)
            print_info(f"\n[*] Full report generated: {report_file}")
    else:
        print_error("\n[!] Unable to perform analysis due to lack of data.")

def main():
    parser = argparse.ArgumentParser(description="ThreatSage: AI-Powered Incident Responder")
    
    # Add arguments
    parser.add_argument(
        "--ip",
        type=str,
        help="Suspicious IP address to analyze"
    )
    
    parser.add_argument(
        "--alert",
        type=str,
        help="Free-text security alert to analyze"
    )
    
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a detailed report"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Process based on input type
    if args.alert:
        process_text_alert(args.alert)
    elif args.ip:
        # Compatibility mode for old --ip argument
        print_info(f"[*] Processing IP: {args.ip}")
        threat_intel = ThreatIntelligence()
        enriched_data = threat_intel.enrich_ip(args.ip)
        
        if "Error" in enriched_data:
            print_error(f"[!] Error during enrichment: {enriched_data['Error']}")
            return
        
        # Print enrichment data
        for key, value in enriched_data.items():
            if key == "Reputation" and value == "Suspicious":
                print_warning(f"{key}: {value}")
            else:
                print(f"{key}: {value}")
        
        # Analyze with agent
        print_info("\n[*] Analyzing threat data...")
        responder = IncidentResponder()
        analysis = responder.reason(enriched_data)
        
        # Display threat score
        score = analysis['threat_score']
        score_color = "31" if score > 70 else "33" if score > 30 else "32"
        print(f"  - Threat score: \033[{score_color}m{score}/100\033[0m")
        
        # Display recommendation
        print_info("\n[*] ThreatSage recommendation:")
        print("  " + analysis['recommendation'].replace('\n', '\n  '))
        
        # Generate report if requested
        if args.report:
            entities = {"ips": [args.ip], "usernames": [], "actions": [], "times": []}
            ip_data = {args.ip: enriched_data}
            report_file = generate_report(entities, ip_data, analysis, f"IP analysis for {args.ip}")
            print_info(f"\n[*] Full report generated: {report_file}")
    else:
        print_error("[!] No input provided. Use --ip or --alert.")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()