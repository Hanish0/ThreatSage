import re
import ipaddress

class EntityExtractor:
    """
    Extract entities like IPs, usernames, and actions from free-text security alerts
    """
    
    def __init__(self):
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.username_pattern = r'(?:user|account|username|login)[\s:]+([a-zA-Z0-9_\-\.]+)'
        self.time_pattern = r'\b(?:\d{1,2}[:]\d{2}(?::\d{2})?(?:\s*[AP]M)?)\b'
        self.action_keywords = [
            'login', 'logon', 'access', 'authentication', 'attempt',
            'failed', 'success', 'connect', 'connection', 'SSH', 'RDP',
            'brute-force', 'attack', 'scan', 'probe'
        ]
    
    def _is_valid_ip(self, ip_str):
        """Validate if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def extract_ips(self, text):
        """Extract IP addresses from text"""
        ip_matches = re.findall(self.ip_pattern, text)
        return [ip for ip in ip_matches if self._is_valid_ip(ip)]
    
    def extract_usernames(self, text):
        """Extract usernames from text"""
        username_matches = re.findall(self.username_pattern, text, re.IGNORECASE)
        return username_matches
    
    def extract_times(self, text):
        """Extract time references from text"""
        time_matches = re.findall(self.time_pattern, text)
        return time_matches
    
    def extract_actions(self, text):
        """Extract security-related actions from text"""
        found_actions = []
        text_lower = text.lower()
        
        for keyword in self.action_keywords:
            if keyword.lower() in text_lower:
                found_actions.append(keyword)
                
        return found_actions
    
    def extract_all(self, text):
        """Extract all entities from alert text"""
        return {
            "ips": self.extract_ips(text),
            "usernames": self.extract_usernames(text),
            "times": self.extract_times(text),
            "actions": self.extract_actions(text),
            "original_text": text
        }