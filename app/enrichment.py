import requests
import time
import hashlib

class ThreatIntelligence:
    """Enhanced threat intelligence gathering from multiple sources"""
    
    def __init__(self):
        # Cache to avoid repeated lookups
        self._cache = {}
        self.cache_ttl = 3600  # 1 hour cache lifetime
    
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
    
    def enrich_ip(self, ip_address):
        """
        Enrich an IP address with threat intelligence
        Returns a dictionary with IP intelligence
        """
        # Check cache first
        cached = self._check_cache("ip", ip_address)
        if cached:
            return cached
        
        # Begin with basic IP-API data
        basic_data = self._query_ip_api(ip_address)
        
        # Check AbuseIPDB reputation (simulated)
        reputation = self._check_abuseipdb(ip_address)
        
        # Combine all intelligence
        combined_data = {**basic_data, **reputation}
        
        # Update cache
        self._update_cache("ip", ip_address, combined_data)
        
        return combined_data
    
    def _query_ip_api(self, ip_address):
        """Query ip-api.com for basic IP intelligence"""
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=5)
            data = response.json()
            
            if data["status"] == "success":
                return {
                    "IP": data.get("query", "N/A"),
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
        except Exception as e:
            return {"Error": str(e)}
    
    def _check_abuseipdb(self, ip_address):
        """
        Simulate AbuseIPDB check (not actually calling the API since it requires a key)
        In a real implementation, you would call the actual API
        """
        # For demonstration purposes, we'll classify some IP ranges as suspicious
        # This would be replaced with actual API calls in production
        suspicious = False
        high_confidence = False
        
        # Check if IP is in certain ranges (purely for demonstration)
        octets = ip_address.split('.')
        if len(octets) == 4:
            # IPs in 185.x.x.x range are considered suspicious for this demo
            if octets[0] == "185":
                suspicious = True
                high_confidence = True
            # Class A private networks (demonstration only)  
            elif octets[0] == "10":
                suspicious = False
            # Special use IPs
            elif octets[0] == "192" and octets[1] == "168":
                suspicious = False
        
        return {
            "Reputation": "Suspicious" if suspicious else "Clean",
            "Confidence": "High" if high_confidence else "Low",
            "AbuseIPDB": "Simulated check - not real data",
        }