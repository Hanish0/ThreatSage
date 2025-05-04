# ThreatSage 🛡️

Hey there! Welcome to **ThreatSage** - an open-source cybersecurity assistant I built to help security professionals make sense of their alerts. It uses AI to enrich threat data and generate actionable recommendations without relying on expensive commercial tools.

After getting tired of manually investigating endless security alerts at work, I created ThreatSage to automate the boring stuff and let analysts focus on what matters. It's designed with smaller teams and indie security researchers in mind - people who need quality intel without enterprise budgets.

## ✨ What Makes ThreatSage Special?

ThreatSage isn't just another threat intel platform - it's a completely different approach that combines:

- **🔍 Natural Language Understanding**: Throw any security alert at it in plain English - "Suspicious login from IP 1.2.3.4 at 3am" works just fine!
- **🌐 Automatic IP Intelligence**: Gets location, ASN, and reputation data automatically using free APIs
- **🧠 Local AI Reasoning**: Uses an offline cybersecurity-focused LLM, so your security data stays on your machine
- **📊 Visual Threat Analysis**: Generates interactive maps and charts that help you spot patterns 
- **💾 Threat Memory**: Remembers past incidents, so recurring threats get identified faster over time
- **🚫 Zero Cost**: Built entirely with free & open-source tools - no API keys or subscriptions needed



---

## 🚀 Getting Started

### What You'll Need

- Python 3.10+ 
- About 5GB of disk space (mostly for the AI model)
- Basic familiarity with running Python apps
- Internet connection (for IP lookups only)

### Quick Setup

I've tried to make installation as painless as possible. Just follow these steps:

#### For Linux & macOS Friends

```bash
# Grab the code
git clone https://github.com/Hanish0/ThreatSage.git
cd ThreatSage

# Set up your environment
python3 -m venv venv
source venv/bin/activate

# Install the dependencies
pip install -r requirements.txt

# Run it!
python -m app.main
```

#### For Windows Users

```powershell
# Clone the repo
git clone https://github.com/Hanish0/ThreatSage.git
cd ThreatSage

# Create your virtual environment
python -m venv venv
venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Fire it up!
python -m app.main
```

That's it! You should see the ThreatSage banner and be greeted with the interactive prompt.

### 🧩 Usage Options

ThreatSage is flexible - use it however it fits into your workflow:

```bash
# Interactive mode - best for ad-hoc analysis
python -m app.main

# Run through sample security scenarios
python -m app.scenarios

# See various demos and capabilities
python -m app.examples
```

Pro tip: For regular usage, I personally add an alias to my `.bashrc` or `.zshrc`:
```bash
alias threatsage="cd /path/to/ThreatSage && source venv/bin/activate && python -m app.main"
```

## 🔎 Real-World Examples

### Example 1: Investigating an Unknown Login

Let's say you get an alert about an admin login from a suspicious IP:

```
[ThreatSage]> Admin login from 185.107.56.21 at 3:44 AM (unusual location)

[*] Processing alert: Admin login from 185.107.56.21 at 3:44 AM (unusual location)

[*] Enriching 1 IPs...
    ✓ 185.107.56.21: The Netherlands - NFOrce Entertainment BV
    ⚠ Reputation: Suspicious (High confidence)

[*] Analyzing threat data...
  - Threat score: 70/100

[*] ThreatSage recommendation:
  This login appears highly suspicious. The IP is associated with a known
  hosting provider in the Netherlands with reported malicious activity.
  The unusual time (3:44 AM) combined with admin access suggests potential
  account compromise.
  
  Recommended actions:
  1) Lock the admin account immediately
  2) Force password reset across all admin accounts
  3) Enable MFA if not already in place
  4) Review all activities performed during this session
  5) Check for newly created accounts or modified permissions
```

### Example 2: Analyzing Multiple IPs

ThreatSage can handle multiple IPs in a single alert:

```
[ThreatSage]> Failed SSH authentication attempts from 45.13.22.98 and 67.43.156.89

[*] Processing alert: Failed SSH authentication attempts from 45.13.22.98 and 67.43.156.89

[*] Enriching 2 IPs...
    ✓ 45.13.22.98: Germany - Avacon Connect GmbH
    ⚠ Reputation: Suspicious (High confidence)
    ✓ 67.43.156.89: United States - Under Radio Net
    
[*] Analyzing threat data...
  - Threat score: 65/100

[*] ThreatSage recommendation:
  Multiple SSH brute force attempts detected from geographically dispersed
  locations, suggesting a coordinated attack...
```

## 🧠 How ThreatSage Works

The "magic" behind ThreatSage happens in a 5-step workflow I designed to mimic how human analysts think:

1. **Text Understanding**: First, it parses the alert text to extract IPs, users, actions, and timestamps using regex and NLP techniques
2. **Intelligence Gathering**: For each IP, it gathers location, ASN, hosting info, and reputation data from free sources
3. **Risk Analysis**: Calculates a threat score based on multiple factors including IP reputation, hosting status, and time of day
4. **AI Reasoning**: Processes all the data through a locally-running LLM to generate human-like security recommendations
5. **Memory & Reporting**: Updates its memory of previous incidents and generates detailed reports and visualizations

Each component is modular, so you can extend or customize any part of the pipeline.

## 📁 Project Structure 

Here's a quick tour of the codebase if you want to dive in:

```
ThreatSage/
├── app/                       # Core application code
│   ├── agent.py              # AI reasoning engine - the "brain"
│   ├── enrichment.py         # IP intelligence gathering
│   ├── extractor.py          # Entity extraction from text
│   ├── main.py               # CLI and interactive mode
│   ├── reporter.py           # Report generation
│   ├── scenarios.py          # Sample security scenarios
│   └── visualizer.py         # Maps and charts generation
├── utils/
│   └── logger.py             # Logging and warning suppression
├── data/                     # Sample data and resources
├── reports/                  # Generated incident reports 
├── visualizations/           # Generated maps and charts
└── requirements.txt          # Project dependencies
```

## 📊 Visualization Capabilities

One thing I'm particularly proud of is the visualization system:

### IP Location Maps

ThreatSage generates interactive HTML maps showing where suspicious IPs are located, including:
- Color-coded markers based on threat level
- Pop-up details with IP info when you click
- Ability to spot geographic patterns across multiple incidents

### Threat History Charts

The threat history visualization helps you track security posture over time:
- Timeline of threat scores
- Trend analysis for recurring issues
- Ability to correlate spikes with specific events

Just run any analysis and choose "Generate map" or "Generate chart" from the post-analysis menu.

## 🔧 Advanced Configuration

### Custom LLM Models

ThreatSage works with various local LLMs, but here's what I recommend:

- **Best Quality**: [Lily-Cybersecurity-7B](https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2) - A model specifically fine-tuned for cybersecurity
- **Balanced**: [Mistral-7B-Instruct](https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.2) - Good reasoning with lower resource usage
- **Low Resources**: [TinyLlama](https://huggingface.co/TinyLlama/TinyLlama-1.1B) - Works on almost any machine, but less sophisticated analysis

To use a different model, edit the `model_name` parameter in `app/agent.py`.

### Proxy Configuration

If you're behind a corporate proxy, set these environment variables:

```bash
export HTTP_PROXY="http://proxy.example.com:8080"
export HTTPS_PROXY="http://proxy.example.com:8080"
```

### Memory Settings

By default, ThreatSage remembers the last 100 incidents. If you're analyzing large datasets, you might want to increase this limit in `app/agent.py`:

```python
# Change from
if len(self.memory["incidents"]) > 100:
    self.memory["incidents"] = self.memory["incidents"][-100:]

# To something larger
if len(self.memory["incidents"]) > 1000:
    self.memory["incidents"] = self.memory["incidents"][-1000:]
```

## 🚧 Current Limitations & Roadmap

ThreatSage is still evolving. Here's what I'm currently working on:

**Current Limitations:**
- Only uses gpt2 by default (the LLM integration needs improvement)
- Limited to IP-based analysis (no URLs or file hashes yet)
- Basic MITRE ATT&CK mapping
- No integration with external security tools

**Coming Soon:**
- Domain and URL enrichment
- File hash reputation lookups
- SIEM (Security Information and Event Management) integration modules
- Better customization of threat scoring
- Improved report templates
- Direct export to popular security platforms

If you'd like to help with any of these, contributions are very welcome!

## 🤝 Contributing

I built ThreatSage to scratch my own itch, but I'd love your help making it better! If you want to contribute:

1. Fork the repo
2. Create a feature branch (`git checkout -b amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit (`git commit -m 'Add some amazing feature'`)
6. Push (`git push origin amazing-feature`)
7. Open a Pull Request

No contribution is too small! Bug fixes, documentation improvements, and feedback are all valuable.

## 📜 License

This project is licensed under the MIT License - basically, do what you want with it, just don't hold me liable!

---

If ThreatSage helps you out, consider giving the repo a star ⭐ It helps others find the project and motivates me to keep improving it!

Questions or feedback? Reach me at [GitHub Issues](https://github.com/Hanish0/ThreatSage/issues)