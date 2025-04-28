import time
import inquirer  # For interactive CLI
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

def process_alert_or_ip(input_text, is_ip=False, generate_report_flag=False, generate_map=False, generate_chart=False):
    """Process an IP address or alert text with visualization options"""
    print_info(f"[*] Processing {'IP' if is_ip else 'alert'}: {input_text}")
    
    # Step 1: Extract entities from alert if it's a free-text alert, or handle IP
    entities = {"ips": [], "usernames": [], "actions": [], "times": []}
    if is_ip:
        entities["ips"] = [input_text]  # It's just a single IP for IP analysis
    else:
        # Extract entities if it's an alert
        extractor = EntityExtractor()
        entities = extractor.extract_all(input_text)
    
    # Step 2: Enrich IPs (if any) with threat intelligence
    threat_intel = ThreatIntelligence()
    ip_data = {}
    
    if entities['ips']:
        print_info(f"\n[*] Enriching {len(entities['ips'])} IPs...")
        for ip in entities['ips']:
            ip_data[ip] = threat_intel.enrich_ip(ip)
            
            if "Error" in ip_data[ip]:
                print_error(f"    ✘ Error: {ip_data[ip]['Error']}")
            else:
                print_success(f"    ✓ {ip}: {ip_data[ip]['Country']} - {ip_data[ip]['Organization']}")
                if ip_data[ip].get('Reputation') == 'Suspicious':
                    print_warning(f"    ⚠ Reputation: {ip_data[ip]['Reputation']} ({ip_data[ip]['Confidence']} confidence)")
    else:
        print_warning("\n[!] No IP addresses found in the input.")
        
    # Step 3: Analyze with agent
    print_info("\n[*] Analyzing threat data...")
    responder = IncidentResponder()
    
    if entities['ips'] and ip_data.get(entities['ips'][0]):
        analysis = responder.reason(ip_data[entities['ips'][0]], raw_alert=input_text)
        
        score = analysis['threat_score']
        score_color = "31" if score > 70 else "33" if score > 30 else "32"
        print(f"  - Threat score: \033[{score_color}m{score}/100\033[0m")
        
        print_info("\n[*] ThreatSage recommendation:")
        print("  " + analysis['recommendation'].replace('\n', '\n  '))
        
        # Generate report if requested
        if score > 50 or generate_report_flag:
            report_file = generate_report(entities, ip_data, analysis, input_text)
            print_info(f"\n[*] Full report generated: {report_file}")
        
        visualizations = []
        
        if generate_map and ip_data:
            print_info("\n[*] Generating IP location map...")
            map_file = generate_html_map(ip_data)
            visualizations.append(map_file)
            print_success(f"  ✓ IP Map generated: {map_file}")
        
        if generate_chart:
            print_info("\n[*] Generating threat history chart...")
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

def get_post_analysis_actions():
    """Prompt user for actions to take after analysis"""
    actions = [
        ("Generate report", "report"),
        ("Generate IP location map", "map"),
        ("Generate threat history chart", "chart"),
        ("Start new analysis", "new"),
        ("Exit", "exit")
    ]
    
    questions = [
        inquirer.Checkbox(
            'actions',
            message="What would you like to do next? (select multiple options using space)",
            choices=actions
        )
    ]
    
    answers = inquirer.prompt(questions)
    return answers['actions'] if answers else []

def interactive_mode():
    """Run ThreatSage in interactive mode"""
    print_banner()
    print_info("[*] Welcome to ThreatSage Interactive Mode")
    print_info("[*] This tool helps analyze security threats and generate reports")
    
    while True:
        # Ask user to input either IP or alert text
        questions = [
            inquirer.Text(
                'input_text',
                message="Enter an IP address or security alert to analyze"
            )
        ]
        input_answer = inquirer.prompt(questions)
        if not input_answer:
            continue
            
        input_text = input_answer['input_text']
        
        # Determine if it's an IP or alert text
        is_ip = '.' in input_text and all(part.isdigit() for part in input_text.split('.'))  # Basic IP check
        
        # Process the input (IP or alert)
        result = process_alert_or_ip(input_text, is_ip=is_ip)
        
        if result:
            # If we have analysis results, offer additional actions
            while True:
                actions = get_post_analysis_actions()
                
                if "exit" in actions:
                    print_info("[*] Exiting ThreatSage.")
                    return
                
                if "new" in actions:
                    # Restart the loop for a new analysis
                    break
                
                # Handle each selected action
                if "report" in actions:
                    # Generate report
                    if "analysis" not in result:
                        print_error("[!] Cannot generate report, missing analysis data")
                        continue
                    
                    report_file = generate_report(
                        result.get("entities", {"ips": []}),
                        result.get("ip_data", {}),
                        result["analysis"],
                        "ThreatSage Interactive Analysis"
                    )
                    print_info(f"\n[*] Full report generated: {report_file}")
                
                if "map" in actions:
                    # Generate IP location map
                    if "ip_data" not in result or not result["ip_data"]:
                        print_error("[!] Cannot generate map, missing IP data")
                        continue
                    
                    print_info("\n[*] Generating IP location map...")
                    map_file = generate_html_map(result["ip_data"])
                    print_success(f"  ✓ IP Map generated: {map_file}")
                
                if "chart" in actions:
                    # Generate threat history chart
                    print_info("\n[*] Generating threat history chart...")
                    responder = IncidentResponder()
                    history = responder.memory.get("incidents", [])
                    
                    if not history:
                        print_warning("  ⚠ No threat history available for charting")
                        continue
                    
                    chart_file = generate_threat_chart(history)
                    print_success(f"  ✓ Threat history chart generated: {chart_file}")


if __name__ == "__main__":
    interactive_mode()
