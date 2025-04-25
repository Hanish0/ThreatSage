import requests

def enrich_ip(ip_address: str) -> dict:
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
                "Is Proxy": data.get("proxy", False),
                "Is Hosting": data.get("hosting", False),
                "Timezone": data.get("timezone", "N/A")
            }
        else:
            return {"Error": f"IP lookup failed: {data.get('message','Unknown error')}"}
    except Exception as e:
        return {"Error": str(e)}