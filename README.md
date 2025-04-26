# ThreatSage

**ThreatSage** is an open-source, agentic AI-powered tool that enriches cybersecurity threat data and generates intelligent incident response recommendations using free LLMs.

## 🚀 Features
- **Free-text Alert Processing**: Parse security alerts in natural language to extract IPs, users, and actions
- **IP Address Enrichment**: Retrieves country, city, ISP, hosting status, and reputation using free IP intelligence APIs
- **Reasoning Engine**: Uses an open-source LLM to generate recommended actions based on the threat intelligence gathered
- **Threat Scoring**: Calculates a confidence score for potential security threats
- **Report Generation**: Creates detailed markdown reports for security incidents
- **Agent Memory**: Tracks previously seen IPs and security incidents
- **Modular and Extensible**: Designed for easy extension to domains like domains, URLs, hashes, and more
- **No Paid APIs / Models**: Built entirely with free APIs and LLMs to make cybersecurity AI accessible to everyone

---

## 🛠️ Project Structure

```
ThreatSage/
└── app/
    ├── agent.py         # Reasoning and recommendation engine
    ├── enrichment.py    # IP and threat intelligence enrichment
    ├── extractor.py     # Entity extraction from text alerts
    ├── main.py          # CLI entry point
    ├── examples.py      # Example usage demos
    ├── reporter.py      # Report generation module
    ├── scenarios.py     # Sample security scenarios
├── data/
    └── sample_scenarios.json # Sample security alerts
├── reports/             # Generated security reports
├── memory_dump.txt      # Agent memory persistence
├── README.md            # Project documentation
└── requirements.txt     # Project dependencies
```

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/ThreatSage.git
cd ThreatSage

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 👤 Usage

### Process a Security Alert

```bash
python -m app.main --alert "Multiple failed SSH logins from IP 45.13.22.98 for root account"
```

### Analyze an IP Address

```bash
python -m app.main --ip 185.107.56.21
```

### Generate a Full Report

```bash
python -m app.main --ip 185.107.56.21 --report
```

### Run Demo Scenarios

```bash
python -m app.scenarios
```

---

## 🧠 Sample Workflow

ThreatSage follows a 5-step reasoning process:

1. **Extract Entities**: Parse alert text for IPs, users, timestamps
2. **Gather Intelligence**: Enrich IPs with location and reputation data
3. **Calculate Threat Score**: Determine severity based on multiple factors
4. **Generate Recommendation**: Use LLM to reason about the appropriate response
5. **Create Report**: Document findings and suggested actions

---

## 📊 Sample Output

**Input:** `"Admin login from 185.107.56.21 at 3:44 AM (unusual location)."`

**Agent Output:**
```
[*] Processing alert: Admin login from 185.107.56.21 at 3:44 AM (unusual location).

[*] Extracted entities:
  IPs: 185.107.56.21
  Usernames: None
  Actions: login

[*] Enriching 1 IPs...
  - Processing 185.107.56.21...
    ✓ 185.107.56.21: The Netherlands - NFOrce Entertainment BV
    ⚠ Reputation: Suspicious (High confidence)

[*] Analyzing threat data...
  - Threat score: 70/100

[*] ThreatSage recommendation:
  This login appears to be highly suspicious. The IP address 185.107.56.21 is associated with known malicious activity and originates from a hosting provider in The Netherlands. The unusual time (3:44 AM) combined with admin access makes this a potential account compromise. Immediate action is recommended: 1) Lock the admin account 2) Force password reset 3) Enable MFA if not already in place 4) Review all activities performed during this session.
```

---

## 🧐 Technology Stack
- Python 3.10+
- Huggingface Transformers (Free GPT-2 pipeline)
- Tensorflow (backend optimization)
- ip-api.com (for free IP enrichment)

---

## 📈 Future Roadmap
- 🔒 Add domain and URL enrichment
- 🛡️ Expand reasoning with open-source cybersecurity LLMs
- 🎯 Create agent memory for multi-turn reasoning
- 🛠️ Integrate basic threat scoring and alerts

---

## 🤝 Contributions

Contributions, bug reports, and feature suggestions are welcome!  
Feel free to open an issue or submit a pull request. 🛠️

---

## 📄 License
This project is licensed under the MIT License.

---