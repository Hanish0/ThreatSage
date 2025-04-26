import argparse
from app.enrichment import enrich_ip
from app.agent import IncidentResponder

def main():
    
    parser = argparse.ArgumentParser(description="ThreatSage: AI-Powered Incident Responder")
    parser.add_argument(
        "--ip",
        type=str,
        required=True,
        help="Suspicious IP address to analyze"
    )
    args = parser.parse_args()
    print(f"\n[+] Enriching IP: {args.ip}")
    enriched_data = enrich_ip(args.ip)

    if "Error" in enriched_data:
        print(f"[!] Error during enrichment: {enriched_data['Error']}")
        return

    for key, value in enriched_data.items():
        print(f"{key}: {value}")

    print("\n[+] Reasoning about the IP...")
    responder = IncidentResponder()
    recommendation = responder.reason(enriched_data)

    print("\n[+] ThreatSage Recommendation:")
    print(recommendation)

if __name__ == "__main__":
    main()
