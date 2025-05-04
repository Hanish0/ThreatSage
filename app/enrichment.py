import requests
import time
import hashlib
import json
import os
import ipaddress

class ThreatIntelligence:
    """Enhanced threat intelligence gathering from multiple sources"""
    
    def __init__(self, cache_dir="./cache"):
        # Create cache directory if it doesn't exist
        self.cache_dir = cache_dir 
        os.makedirs(cache_dir, exist_ok=True)
        
        # Cache to avoid repeated lookups
        self._load_cache()
        self.cache_ttl = 3600  # 1 hour cache lifetime
    
    def _load_cache(self):
        """Load cache from disk"""
        cache_file = os.path.join(self.cache_dir, "ip_cache.json")
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    self._cache = json.load(f)
            else:
                self._cache = {}
        except Exception as e:
            print(f"Warning: Could not load cache: {e}")
            self._cache = {}
    
    def _save_cache(self):
        """Save cache to disk"""
        cache_file = os.path.join(self.cache_dir, "ip_cache.json")
        try:
            with open(cache_file, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save cache: {e}")
    
    def _cache_key(self, item_type, item_value):
        """Generate a cache key for any type of indicator"""
        return f"{item_type}:{hashlib.md5(item_value.encode()).hexdigest()}"
    
    def _check_cache(self, item_type, item_value):
        """Check if we have cached data for this indicator"""
        key = self._cache_key(item_type, item_value)
        if key in self._cache:
            timestamp, data = self._cache[key]
            if time.time() - timestamp < self.cache_ttl:
                return data
        return None
    
    def _update_cache(self, item_type, item_value, data):
        """Update cache with fresh data"""
        key = self._cache_key(item_type, item_value)
        self._cache[key] = (time.time(), data)
        # Periodically save cache to disk (every 10 updates)
        if len(self._cache) % 10 == 0:
            self._save_cache()
    
    def enrich_ip(self, ip_address):
        """
        Enrich an IP address with threat intelligence
        Returns a dictionary with IP intelligence
        """
        if not ip_address:
            return {"Error": "No IP address provided"}
            
        # Check if the IP is a private address
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return {
                    "IP": ip_address,
                    "Type": "Private IP",
                    "Note": "This is a private network address, no external intelligence available",
                    "Country": "Internal Network",
                    "Is Internal": True,
                    "Reputation": "Not Applicable"
                }
        except ValueError:
            pass
            
        # Check cache first
        cached = self._check_cache("ip", ip_address)
        if cached:
            return cached
        
        # Begin with basic IP-API data
        basic_data = self._query_ip_api(ip_address)
        
        # Stop if we couldn't get basic data
        if "Error" in basic_data:
            return basic_data
        
        # Check AbuseIPDB reputation (simulated)
        reputation = self._check_abuseipdb(ip_address)
        
        # Combine all intelligence
        combined_data = {**basic_data, **reputation}
        
        # Update cache
        self._update_cache("ip", ip_address, combined_data)
        
        return combined_data
    
    def _query_ip_api(self, ip_address):
        """Query ip-api.com for basic IP intelligence with better error handling"""
        try:
            # ip-api.com free tier uses the http endpoint, not https
            url = f"http://ip-api.com/json/{ip_address}"
            
            # Add proper user agent and headers to avoid being blocked
            headers = {
                "User-Agent": "ThreatSage/1.0 (https://github.com/Hanish0/ThreatSage)",
                "Accept": "application/json",
            }
            
            response = requests.get(url, headers=headers, timeout=5)
            
            # Check if we got a response
            if response.status_code != 200:
                return {"Error": f"IP lookup failed with status code: {response.status_code}"}
                
            data = response.json()
            
            if data["status"] == "success":
                return {
                    "IP": data.get("query", ip_address),
                    "Country": data.get("country", "N/A"),
                    "Region": data.get("regionName", "N/A"),
                    "City": data.get("city", "N/A"),
                    "ISP": data.get("isp", "N/A"),
                    "Organization": data.get("org", "N/A"),
                    "ASN": data.get("as", "N/A"),
                    "Is Proxy": data.get("proxy", False),
                    "Is Hosting": data.get("hosting", False),
                    "Is Mobile": data.get("mobile", False),
                    "Timezone": data.get("timezone", "N/A"),
                    "Coordinates": f"{data.get('lat', 'N/A')},{data.get('lon', 'N/A')}",
                }
            else:
                return {"Error": f"IP lookup failed: {data.get('message','Unknown error')}"}
        except requests.exceptions.ConnectTimeout:
            return {"Error": "Connection timed out while fetching IP data", 
                    "IP": ip_address, 
                    "Fallback": True}
        except requests.exceptions.RequestException as e:
            return {"Error": f"Request failed: {str(e)}", 
                    "IP": ip_address, 
                    "Fallback": True}
        except Exception as e:
            return {"Error": f"Unexpected error: {str(e)}", 
                    "IP": ip_address, 
                    "Fallback": True}
    
    def _check_abuseipdb(self, ip_address):
        """
        Improved AbuseIPDB simulation with more realistic data
        """
        # For demonstration purposes, we'll classify some IP ranges as suspicious
        # This would be replaced with actual API calls in production
        suspicious = False
        high_confidence = False
        
        # Check if IP is in certain ranges (purely for demonstration)
        octets = ip_address.split('.')
        if len(octets) == 4:
            # Known malicious IP ranges (demonstration only)
            if octets[0] == "185":
                suspicious = True
                high_confidence = True
            elif octets[0] == "45" and octets[1] == "13":
                suspicious = True  
                high_confidence = True
            # Tor exit nodes common prefix (demonstration)
            elif octets[0] == "176" and octets[1] == "10":
                suspicious = True
                high_confidence = False
            # Class A private networks (demonstration only)  
            elif octets[0] == "10":
                suspicious = False
            # Special use IPs
            elif octets[0] == "192" and octets[1] == "168":
                suspicious = False
        
        result = {
            "Reputation": "Suspicious" if suspicious else "Clean",
            "Confidence": "High" if high_confidence else "Low",
            "AbuseIPDB": "Simulated check - not real data",
        }
        
        # For suspicious IPs, add simulated reports
        if suspicious:
            result["Reported Activities"] = []
            
            if high_confidence:
                result["Reported Activities"] = [
                    "Brute-force login attempts",
                    "Web scanning activity", 
                    "SSH dictionary attacks"
                ]
            else:
                result["Reported Activities"] = ["Suspicious connection attempts"]
                
        return result
        
    def enrich_domain(self, domain):
        """
        Placeholder for domain enrichment functionality
        """
        return {
            "Domain": domain,
            "Status": "Not implemented yet",
            "Note": "Domain enrichment will be available in a future release"
        }