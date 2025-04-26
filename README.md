# ThreatSage

**ThreatSage** is an open-source, agentic AI-powered tool that enriches cybersecurity threat data and generates intelligent incident response recommendations using free LLMs.

## 🚀 Features
- **IP Address Enrichment**: Retrieves country, city, ISP, hosting status, and more using free IP intelligence APIs.
- **Reasoning Engine**: Uses an open-source LLM to generate recommended actions based on the threat intelligence gathered.
- **Modular and Extensible**: Designed for easy extension to domains like domains, URLs, hashes, and more.
- **No Paid APIs / Models**: Built entirely with free APIs and LLMs to make cybersecurity AI accessible to everyone.

---

## 🛠️ Project Structure

```
ThreatSage/
🖋️ app/
│   🖋️ enrichment.py   # Module to enrich IP addresses
│   🖋️ responder.py    # Module for reasoning and recommendation
│   🖋️ main.py         # CLI entry point
│   🖋️ examples.py     # Example usage scripts
🖋️ memory_dump.txt     # Progress tracking file
🖋️ README.md           # Project documentation
🖋️ requirements.txt    # Project dependencies
```

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/ThreatSage.git
cd ThreatSage

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 👤 Usage

**Example**: Enrich an IP and get a recommendation:

```bash
python3 -m app.main --ip 185.107.56.21
```

**Sample Output**:
```
[+] Enriching IP: 185.107.56.21
Country: The Netherlands
City: Roosendaal
ISP: NFOrce Entertainment BV
...
[+] ThreatSage Recommendation:
Review the hosting provider's abuse policies and verify potential compromise.
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
