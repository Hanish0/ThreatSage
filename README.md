# ThreatSage

**ThreatSage** is an open-source, agent-based tool that enriches cybersecurity threat data and generates intelligent incident response recommendations using local language models.

## Features

- **Free-text Alert Processing**: Parse security alerts in natural language to extract IPs, users, and actions
- **IP Address Enrichment**: Retrieves country, city, ISP, hosting status, and reputation using free IP intelligence APIs
- **Reasoning Engine**: Uses local LLMs to generate recommended actions based on the threat intelligence gathered
- **Threat Scoring**: Calculates a confidence score for potential security threats
- **Report Generation**: Creates detailed markdown reports for security incidents
- **Agent Memory**: Tracks previously seen IPs and security incidents
- **Modular and Extensible**: Designed for easy extension to domains like domains, URLs, hashes, and more
- **No Paid APIs / Models**: Built entirely with free APIs and LLMs to make cybersecurity AI accessible to everyone

---

## Project Structure

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
    ├── visualizer.py    # IP maps and threat chart generation
├── data/
    └── sample_scenarios.json # Sample security alerts
├── reports/             # Generated security reports
├── visualizations/      # Generated maps and charts
├── utils/
    └── logger.py        # Logging configuration
├── memory_dump.txt      # Agent memory persistence
├── README.md            # Project documentation
└── requirements.txt     # Project dependencies
```

---

## Installation

### Prerequisites

- Python 3.10 or higher
- Internet connection for IP intelligence API requests

### Installation Steps

#### Linux/macOS

```bash
# Clone the repository
git clone https://github.com/yourusername/ThreatSage.git
cd ThreatSage

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### Windows

```bash
# Clone the repository
git clone https://github.com/yourusername/ThreatSage.git
cd ThreatSage

# Create a virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### LLM Selection

ThreatSage uses Hugging Face Transformers to load language models. While the default fallback model is GPT-2, it is **not recommended for production use** as it produces limited and sometimes hallucinated results. For better analysis, we recommend:

1. **segolilylabs/Lily-Cybersecurity-7B-v0.2** - A specialized cybersecurity model that provides excellent threat analysis (requires ~16GB VRAM)
2. **Quantized versions** - For resource-constrained systems, look for 4-bit or 8-bit quantized versions of Lily-Cybersecurity
3. **Mistral-7B variants** - Good alternatives with solid reasoning capabilities and better performance than GPT-2

You can specify your chosen model in `agent.py` or via a configuration file.

---

## Usage

### Interactive Mode

```bash
python -m app.main
```

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

## Core Workflow

ThreatSage follows a 5-step reasoning process:

1. **Extract Entities**: Parse alert text for IPs, users, timestamps
2. **Gather Intelligence**: Enrich IPs with location and reputation data
3. **Calculate Threat Score**: Determine severity based on multiple factors
4. **Generate Recommendation**: Use LLM to reason about the appropriate response
5. **Create Report**: Document findings and suggested actions

---

## Sample Output

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

## Technical Implementation

ThreatSage combines several technologies to provide comprehensive threat analysis:

- **Python 3.10+** - Core implementation language
- **Hugging Face Transformers** - For loading and running language models
- **PyTorch/TensorFlow** - Backend for machine learning models
- **ip-api.com** - Free IP geolocation and intelligence
- **Chart.js and Leaflet.js** - For visualization capabilities

---

## Visualization Features

ThreatSage provides two types of visual analysis:

1. **IP Location Maps** - Interactive world maps showing the geographic location of suspicious IPs
2. **Threat History Charts** - Timeline visualization of threat scores from previous analyses

These visualizations are generated as standalone HTML files in the `visualizations/` directory.

---

## Future Development Roadmap

- Add domain and URL enrichment capabilities
- Expand reasoning with specialized cybersecurity LLMs
- Enhance agent memory for multi-turn reasoning
- Implement MITRE ATT&CK framework integration
- Add network traffic analysis module
- Improve visualization options

---

## Contributions

Contributions, bug reports, and feature suggestions are welcome. Please feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License.