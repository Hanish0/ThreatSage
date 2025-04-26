# app/scenarios.py
import sys
import os
sys.path.append(os.path.abspath("."))
from app.main import process_text_alert
import json
import time

def load_scenarios():
    """Load sample scenarios from JSON file, or create if not exists"""
    scenarios_file = "data/sample_scenarios.json"
    os.makedirs("data", exist_ok=True)
    
    scenarios = [
        {
            "id": "scenario-001",
            "name": "SSH Brute Force",
            "alert": "Multiple failed SSH logins from IP 45.13.22.98 for root account at 03:44 AM",
            "description": "Detection of potential SSH brute force attack from a suspicious IP",
            "expected_threat_level": "High"
        },
        {
            "id": "scenario-002",
            "name": "Admin Unusual Login",
            "alert": "Admin user john.doe logged in from unusual location IP 185.107.56.21",
            "description": "Admin user logging in from an unusual IP address at an unusual time",
            "expected_threat_level": "Medium"
        },
        {
            "id": "scenario-003",
            "name": "Internal Connection",
            "alert": "Internal firewall blocked connection attempt from 192.168.1.5 to finance server",
            "description": "Internal device attempting to access restricted server",
            "expected_threat_level": "Low"
        },
        {
            "id": "scenario-004",
            "name": "File Share Access",
            "alert": "User susan.wilson@company.com accessed sensitive HR files from remote IP 67.43.156.89",
            "description": "HR file access from remote location",
            "expected_threat_level": "Medium"
        }
    ]
    
    # Create file if doesn't exist
    if not os.path.exists(scenarios_file):
        with open(scenarios_file, "w") as f:
            json.dump({"scenarios": scenarios}, f, indent=2)
    else:
        try:
            with open(scenarios_file, "r") as f:
                loaded = json.load(f)
                scenarios = loaded.get("scenarios", scenarios)
        except json.JSONDecodeError:
            pass
            
    return scenarios

def run_scenario(scenario):
    """Run a single scenario"""
    print(f"\n{'=' * 80}")
    print(f"SCENARIO: {scenario['name']}")
    print(f"DESCRIPTION: {scenario['description']}")
    print(f"{'=' * 80}")
    
    # Process the alert
    process_text_alert(scenario['alert'])
    
    print(f"\n{'=' * 80}\n")
    time.sleep(1)  # Pause between scenarios

def run_all_scenarios():
    """Run all available scenarios"""
    scenarios = load_scenarios()
    
    print("\n" + "=" * 80)
    print("RUNNING THREATSAGE SAMPLE SCENARIOS")
    print("=" * 80 + "\n")
    
    for scenario in scenarios:
        run_scenario(scenario)
        
    print("\nAll scenarios completed.")

if __name__ == "__main__":
    run_all_scenarios()