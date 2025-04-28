import argparse
import sys
import time
from app.enrichment import ThreatIntelligence
from app.agent import IncidentResponder
from app.extractor import EntityExtractor
from app.reporter import generate_report
from app.visualizer import generate_html_map, generate_threat_chart

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

def process_text_alert(alert_text, generate_map=False, generate_chart=False, generate_report_flag=False):
    """Process a free-text security alert with visualization options"""
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
    if entities['ips'] and ip_data.get(entities['ips'][0]):
        analysis = responder.reason(ip_data[entities['ips'][0]], raw_alert=alert_text)
        
        # Display threat score with color coding
        score = analysis['threat_score']
        score_color = "31" if score > 70 else "33" if score > 30 else "32"
        print(f"  - Threat score: \033[{score_color}m{score}/100\033[0m")
        
        # Display recommendation
        print_info("\n[*] ThreatSage recommendation:")
        print("  " + analysis['recommendation'].replace('\n', '\n  '))
        
        # Generate report if score is high or explicitly requested
        if score > 50 or generate_report_flag:
            report_file = generate_report(entities, ip_data, analysis, alert_text)
            print_info(f"\n[*] Full report generated: {report_file}")
        
        # Generate visualization if requested
        visualizations = []
        
        if generate_map and ip_data:
            print_info("\n[*] Generating IP location map...")
            map_file = generate_html_map(ip_data)
            visualizations.append(map_file)
            print_success(f"  ✓ IP Map generated: {map_file}")
        
        if generate_chart:
            print_info("\n[*] Generating threat history chart...")
            # Get history from the responder's memory
            history = responder.memory.get("incidents", [])
            if history:
                chart_file = generate_threat_chart(history)
                visualizations.append(chart_file)
                print_success(f"  ✓ Threat history chart generated: {chart_file}")
            else:
                print_warning("  ⚠ No threat history available for charting")
        
        return {
            "entities": entities,
            "ip_data": ip_data,
            "analysis": analysis,
            "visualizations": visualizations
        }
    else:
        print_error("\n[!] Unable to perform analysis due to lack of data.")
        return None

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
    
    # New visualization arguments
    parser.add_argument(
        "--visualize",
        action="store_true",
        help="Generate all visual representations of the threat data"
    )
    
    parser.add_argument(
        "--map",
        action="store_true",
        help="Generate an interactive map of IP locations"
    )
    
    parser.add_argument(
        "--chart-history",
        action="store_true",
        help="Generate a chart showing threat history over time"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Enable all visualizations if --visualize is specified
    generate_map = args.map or args.visualize
    generate_chart = args.chart_history or args.visualize
    
    # Process based on input type
    if args.alert:
        process_text_alert(
            args.alert, 
            generate_map=generate_map, 
            generate_chart=generate_chart,
            generate_report_flag=args.report
        )
    elif args.ip:
        # Create an alert from the IP for processing
        alert_text = f"Analysis request for IP: {args.ip}"
        print_info(f"[*] Processing IP: {args.ip}")
        
        # Use the same process_text_alert function for consistency
        result = process_text_alert(
            alert_text, 
            generate_map=generate_map, 
            generate_chart=generate_chart,
            generate_report_flag=args.report
        )
        
        if not result:
            # Fallback for direct IP processing if process_text_alert fails
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
            
            # Generate visualization if requested
            if generate_map:
                print_info("\n[*] Generating IP location map...")
                ip_data = {args.ip: enriched_data}
                map_file = generate_html_map(ip_data)
                print_success(f"  ✓ IP Map generated: {map_file}")
            
            if generate_chart:
                print_info("\n[*] Generating threat history chart...")
                # Get history from the responder's memory
                history = responder.memory.get("incidents", [])
                if history:
                    chart_file = generate_threat_chart(history)
                    print_success(f"  ✓ Threat history chart generated: {chart_file}")
                else:
                    print_warning("  ⚠ No threat history available for charting")
    else:
        print_error("[!] No input provided. Use --ip or --alert.")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()