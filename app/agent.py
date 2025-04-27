from transformers import pipeline
import time
import json
import os

class IncidentResponder:
    def __init__(self, model_name='gpt2'): #use 'segolilylabs/Lily-Cybersecurity-7B-v0.2' this model if your system has the capability
        """
        Initialize the Incident Responder agent
        
        Args:
            model_name: Name of the HuggingFace model to use
        """
        # Try to use a better model if available, but fallback to gpt2
        try:
            self.model = pipeline("text-generation", model=model_name, trust_remote_code=True)
            self.model_name = model_name
        except (ImportError, ValueError, OSError) as e:
            print(f"Warning: Could not load {model_name}, falling back to gpt2. Error: {e}")
            self.model = pipeline("text-generation", model="gpt2")
            self.model_name = "gpt2"
            
        self.memory_file = "memory_dump.txt"
        self.load_memory()
    
    def load_memory(self):
        """Load past incidents from memory file with error handling"""
        self.memory = {"incidents": [], "known_ips": {}}
        
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.memory = json.loads(content)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Warning: Could not load memory file: {e}")
                # Initialize empty memory structure instead of failing
                self.memory = {"incidents": [], "known_ips": {}}
    
    def save_memory(self):
        """Save current state to memory file with error handling"""
        try:
            with open(self.memory_file, 'w') as f:
                json.dump(self.memory, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save memory to {self.memory_file}: {e}")
    
    def analyze_ip_history(self, ip_address):
        """Check if IP has been seen before and retrieve history"""
        if not ip_address:
            return {"seen_count": 0, "previous_verdicts": []}
            
        if ip_address in self.memory.get("known_ips", {}):
            return self.memory["known_ips"][ip_address]
        return {"seen_count": 0, "previous_verdicts": []}
    
    def calculate_threat_score(self, enriched_data):
        """
        Calculate a threat score based on IP intelligence
        Returns score from 0-100 (higher is more suspicious)
        """
        score = 0
        
        # Check if it's a proxy or hosting provider
        if enriched_data.get("Is Proxy", False):
            score += 30
        if enriched_data.get("Is Hosting", False):
            score += 20
            
        # Check for history of this IP
        ip = enriched_data.get("IP")
        if ip:
            history = self.analyze_ip_history(ip)
            previous_incidents = history.get("seen_count", 0)
            score += min(previous_incidents * 10, 30)
        
        # Consider reputation directly
        if enriched_data.get("Reputation") == "Suspicious":
            confidence = enriched_data.get("Confidence", "Low")
            if confidence == "High":
                score += 30
            else:
                score += 15
        
        # Check country (simplistic - could be enhanced)
        high_risk_countries = ["Russia", "China", "North Korea", "Iran"]
        if enriched_data.get("Country") in high_risk_countries:
            score += 20
            
        return min(score, 100)  # Cap at 100
    
    def reason(self, enriched_data, raw_alert=None):
        """
        Perform reasoning about the security incident
        
        Args:
            enriched_data: Dictionary of IP intelligence
            raw_alert: Original alert text if available
        
        Returns:
            Dictionary with recommendation and analysis
        """
        # First calculate a threat score
        threat_score = self.calculate_threat_score(enriched_data)
        
        # Create context for LLM
        context = []
        if raw_alert:
            context.append(f"Alert: {raw_alert}")
        
        # Add enriched data
        context.append("IP Intelligence:")
        for key, value in enriched_data.items():
            if key != "Error":
                context.append(f"- {key}: {value}")
        
        # Add threat score
        context.append(f"\nThreat Score: {threat_score}/100")
        
        # Add IP history if available
        ip = enriched_data.get("IP")
        if ip:
            history = self.analyze_ip_history(ip)
            context.append(f"\nIP History:")
            context.append(f"- Previously seen: {history.get('seen_count', 0)} times")
            
            # Add previous verdicts if available
            if history.get("previous_verdicts", []):
                context.append("- Previous incidents:")
                for i, verdict in enumerate(history.get("previous_verdicts", [])[:3]):  # Show only last 3
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', 
                                             time.localtime(verdict.get("timestamp", 0)))
                    context.append(f"  {i+1}. [{timestamp}] Score: {verdict.get('threat_score', 0)}/100")
        
        # Create detailed prompt for better reasoning
        formatted_input = (
            "You are a cybersecurity expert conducting threat analysis.\n"
            "Given the following information, provide a security assessment and recommendation.\n\n"
            f"{chr(10).join(context)}\n\n"
            "Your assessment should include:\n"
            "1. Is this likely a real security threat? Why or why not?\n"
            "2. What MITRE ATT&CK tactics might this relate to?\n"
            "3. What specific actions should the security team take?\n\n"
            "Security Assessment:"
        )

        # Generate reasoning with parameter adjustments based on model
        try:
            if "gpt2" in self.model_name:
                # Limited model capabilities require shorter outputs
                response = self.model(
                    formatted_input, 
                    max_length=400,
                    num_return_sequences=1,
                    temperature=0.7,
                    truncation=True
                )
            else:
                # Better models can provide more detailed reasoning
                response = self.model(
                    formatted_input, 
                    max_length=800,
                    num_return_sequences=1,
                    temperature=0.3,  # Lower temperature for more predictable output
                    top_p=0.85,       # Nucleus sampling for more focused output
                    truncation=True
                )
            
            # Extract the recommendation part
            raw_response = response[0]['generated_text'].split('Security Assessment:')[-1].strip()
            
        except Exception as e:
            print(f"Error generating recommendation: {e}")
            # Provide fallback response if model fails
            raw_response = (
                f"Unable to provide detailed analysis due to a model error. "
                f"Based on the threat score of {threat_score}/100, "
                f"this incident {'requires attention' if threat_score > 50 else 'should be monitored'}."
            )
        
        # Update memory with this incident
        self._update_memory(enriched_data.get("IP"), threat_score, raw_response)
        
        return {
            "threat_score": threat_score,
            "recommendation": raw_response,
            "timestamp": time.time()
        }
    
    def _update_memory(self, ip, threat_score, verdict):
        """Update memory with new incident information"""
        # Skip if no IP (shouldn't happen in normal operation)
        if not ip:
            return
            
        # Initialize if this IP hasn't been seen before
        if "known_ips" not in self.memory:
            self.memory["known_ips"] = {}
            
        if ip not in self.memory["known_ips"]:
            self.memory["known_ips"][ip] = {
                "seen_count": 0,
                "previous_verdicts": []
            }
            
        # Update counters and history
        self.memory["known_ips"][ip]["seen_count"] += 1
        
        # Store a compact version of the verdict
        compact_verdict = {
            "timestamp": time.time(),
            "threat_score": threat_score,
            "summary": verdict[:100] + "..." if len(verdict) > 100 else verdict
        }
        
        self.memory["known_ips"][ip]["previous_verdicts"].append(compact_verdict)
        
        # Limit to last 5 verdicts to prevent unbounded growth
        if len(self.memory["known_ips"][ip]["previous_verdicts"]) > 5:
            self.memory["known_ips"][ip]["previous_verdicts"] = self.memory["known_ips"][ip]["previous_verdicts"][-5:]
            
        # Store this incident
        if "incidents" not in self.memory:
            self.memory["incidents"] = []
            
        self.memory["incidents"].append({
            "ip": ip,
            "timestamp": time.time(),
            "threat_score": threat_score
        })
        
        # Limit to last 100 incidents
        if len(self.memory["incidents"]) > 100:
            self.memory["incidents"] = self.memory["incidents"][-100:]
            
        # Save updated memory
        self.save_memory()