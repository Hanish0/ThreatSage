import sys
import os
sys.path.append(os.path.abspath("."))
from app.enrichment import enrich_ip

if __name__ == "__main__":
    test_ip = "185.107.56.21"
    result = enrich_ip(test_ip)
    for key,value in result.items():
        print(f"{key}: {value}")