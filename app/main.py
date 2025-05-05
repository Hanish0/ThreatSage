"""
ThreatSage - AI-Powered Cybersecurity Intelligence
Main application entry point
"""
import os
import sys

# Use the centralized path setup function
from app import setup_project_path
setup_project_path()

from utils.logger import configure_logging
configure_logging()

import warnings
import logging
import time
import inquirer
import ipaddress

from app.enrichment import ThreatIntelligence
from app.agent import IncidentResponder
from app.extractor import EntityExtractor
from app.reporter import generate_report
from app.visualizer import generate_html_map, generate_threat_chart


def suppress_warnings():
    """Suppress unnecessary warnings for cleaner output"""
    warnings.filterwarnings("ignore")
    logging.getLogger().setLevel(logging.ERROR)


def print_banner():
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

def is_valid_ip(ip_text):
    """Properly validate IP address using ipaddress module"""
    try:
        ipaddress.ip_address(ip_text)
        return True
    except ValueError:
        return False

def process_alert_or_ip(input_text, is_ip=False, generate_report_flag=False, generate_map=False, generate_chart=False, responder=None):
    """Process an IP address or alert text with visualization options"""
    print_info(f"[*] Processing {'IP' if is_ip else 'alert'}: {input_text}")
    
    entities = {"ips": [], "usernames": [], "actions": [], "times": []}
    if is_ip:
        entities["ips"] = [input_text]  
    else:
        extractor = EntityExtractor()
        entities = extractor.extract_all(input_text)
    
    threat_intel = ThreatIntelligence()
    ip_data = {}
    
    if entities['ips']:
        print_info(f"\n[*] Enriching {len(entities['ips'])} IPs...")
        for ip in entities['ips']:
            ip_data[ip] = threat_intel.enrich_ip(ip)
            
            if "Error" in ip_data[ip]:
                print_error(f"    ✘ Error: {ip_data[ip]['Error']}")
            elif ip_data[ip].get("Is Internal", False):
                print_info(f"    ℹ {ip}: {ip_data[ip]['Type']} - {ip_data[ip]['Note']}")
            else:
                print_success(f"    ✓ {ip}: {ip_data[ip]['Country']} - {ip_data[ip]['Organization']}")
                if ip_data[ip].get('Reputation') == 'Suspicious':
                    print_warning(f"    ⚠ Reputation: {ip_data[ip]['Reputation']} ({ip_data[ip]['Confidence']} confidence)")
    else:
        print_warning("\n[!] No IP addresses found in the input.")
        
    print_info("\n[*] Analyzing threat data...")
    # Use the provided responder or create a new one if not provided
    if responder is None:
        responder = IncidentResponder()
    
    if entities['ips'] and ip_data.get(entities['ips'][0]):
        analysis = responder.reason(ip_data[entities['ips'][0]], raw_alert=input_text)
        
        score = analysis['threat_score']
        score_color = "31" if score > 70 else "33" if score > 30 else "32"
        print(f"  - Threat score: \033[{score_color}m{score}/100\033[0m")
        
        print_info("\n[*] ThreatSage recommendation:")
        print("  " + analysis['recommendation'].replace('\n', '\n  '))
        
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
    print_banner()
    print_info("[*] Welcome to ThreatSage Interactive Mode")
    print_info("[*] This tool helps analyze security threats and generate reports")
    
    responder = IncidentResponder()
    
    while True:
        try:
            questions = [
                inquirer.Text(
                    'input_text',
                    message="Enter an IP address or security alert to analyze "
                )
            ]
            input_answer = inquirer.prompt(questions)

            if input_answer is None:
                print_info("\n[*] Exiting ThreatSage.")
                break
            input_text = input_answer['input_text']

            is_ip = is_valid_ip(input_text)  # Improved IP validation
            
            # Pass the shared responder to avoid creating a new instance
            result = process_alert_or_ip(input_text, is_ip=is_ip, responder=responder)

            if result:
                while True:
                    try:
                        actions = get_post_analysis_actions()

                        if "exit" in actions:
                            print_info("[*] Exiting ThreatSage.")
                            return

                        if "new" in actions:
                            break

                        if "report" in actions:
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
                            if "ip_data" not in result or not result["ip_data"]:
                                print_error("[!] Cannot generate map, missing IP data")
                                continue
                            print_info("\n[*] Generating IP location map...")
                            map_file = generate_html_map(result["ip_data"])
                            print_success(f"  ✓ IP Map generated: {map_file}")

                        if "chart" in actions:
                            print_info("\n[*] Generating threat history chart...")
                            # Use the shared responder instance for consistency
                            history = responder.memory.get("incidents", [])
                            if not history:
                                print_warning("  ⚠ No threat history available for charting")
                                continue
                            chart_file = generate_threat_chart(history)
                            print_success(f"  ✓ Threat history chart generated: {chart_file}")
                    except KeyboardInterrupt:
                        print_info("\n[*] Returning to main menu.")
                        break

        except KeyboardInterrupt:
            print_info("\n[*] Exiting ThreatSage.")
            break

if __name__ == "__main__":
    suppress_warnings()
    interactive_mode()
