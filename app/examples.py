import sys
import os
sys.path.append(os.path.abspath("."))
from app.enrichment import enrich_ip
from app.agent import IncidentResponder

def main():
    test_ip = "185.107.56.21"
    enriched_data = enrich_ip(test_ip)
    responder = IncidentResponder()
    recommendation = responder.reason(enriched_data)

    print("Enriched Data:", enriched_data)
    print("Agent Recommendation", recommendation)

if __name__ == "__main__":
    main()