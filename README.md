# 🛡️ URL Attack Detector

> A smart web security tool that analyzes network traffic and server logs to detect cyber attacks in real-time.

[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.2-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-brightgreen.svg)](Dockerfile)

---

## 📖 What is This?

**URL Attack Detector** is a cybersecurity monitoring system that helps protect websites and web applications by automatically identifying malicious activities. Think of it as a security camera for your website that watches all incoming traffic and alerts you when something suspicious happens.

### 🎯 What Problems Does It Solve?

- **Prevents Data Breaches**: Catches hackers trying to steal sensitive information from databases
- **Blocks Malicious Code**: Detects attempts to inject harmful scripts into your website
- **Stops Unauthorized Access**: Identifies brute-force login attempts and credential stuffing
- **Protects Server Files**: Alerts when attackers try to access restricted system files
- **Real-time Monitoring**: Provides instant alerts when attacks are detected

---

## ✨ Key Features

### 🔍 Attack Detection Capabilities

| Attack Type | Description | What It Prevents |
|------------|-------------|------------------|
| **SQL Injection** | Detects database manipulation attempts | Protects user data, passwords, credit cards |
| **XSS (Cross-Site Scripting)** | Identifies malicious script injections | Prevents account hijacking, data theft |
| **Directory Traversal** | Catches unauthorized file access attempts | Blocks access to system files |
| **Command Injection** | Detects attempts to run system commands | Prevents server takeover |
| **SSRF** | Identifies server-side request forgery | Protects internal network resources |
| **RFI/LFI** | Detects remote/local file inclusion | Stops malicious file execution |
| **Credential Stuffing** | Catches brute-force login attempts | Prevents account compromise |
| **XXE Injection** | Identifies XML external entity attacks | Protects sensitive file disclosure |
| **Webshell Detection** | Finds backdoor upload attempts | Prevents persistent server access |

### 💡 User-Friendly Features

- **📊 Visual Dashboard**: Easy-to-read interface showing all detected threats
- **📁 Multiple Input Formats**: Supports PCAP files and Apache/Nginx access logs
- **📈 Confidence Scoring**: Each alert includes a confidence level (0-100%)
- **💾 Export Reports**: Download alerts as CSV for further analysis
- **🔄 Real-time Updates**: Live monitoring and instant alert refreshing
- **🎯 Filter & Search**: Quickly find specific types of attacks

---

## 🚀 Quick Start Guide

### Option 1: Using Docker (Easiest)

Perfect for users who want to get started quickly without installing dependencies.

```bash
# 1. Clone the repository
git clone https://github.com/KshitizSadh/Url-Attack-Detector.git
cd url-attack-detector

# 2. Start the application
docker build -t sih-url-detector .
docker compose up

# 3. Open your browser
Visit http://localhost:5000
```

### Option 2: Manual Installation

For users who prefer traditional setup or need customization.

#### Prerequisites

- Python 3.10 or higher
- TShark (Wireshark command-line tool)

#### Installation Steps

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y tshark

# 2. Clone the repository
git clone https://github.com/KshitizSadh/Url-Attack-Detector.git
cd url-attack-detector

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 4. Install Python packages
pip install -r requirements.txt

# 5. Run the application
export FLASK_APP=app.py
flask run

# 6. Access the dashboard
Open http://127.0.0.1:5000 in your browser
```

---
<img width="1917" height="982" alt="image" src="https://github.com/user-attachments/assets/f6c84c79-389d-4468-be42-a8cbd9333ae7" />

## 📝 How to Use

### Step 1: Upload Your Data

The tool accepts two types of input files:

1. **PCAP Files** (`.pcap`, `.pcapng`)
   - Network packet captures from Wireshark or tcpdump
   - Contains raw network traffic data

2. **Access Logs** (`.log`, `.txt`)
   - Apache or Nginx web server logs
   - Standard combined log format
<img width="1918" height="987" alt="image" src="https://github.com/user-attachments/assets/589dd3c6-162e-4173-8cbc-d232b0b9429f" />

### Step 2: Analyze Traffic

1. Click the **"Upload & Analyze"** button on the dashboard
2. Select your PCAP file or access log
3. Wait for the analysis to complete (usually takes a few seconds)
<img width="1605" height="870" alt="image" src="https://github.com/user-attachments/assets/85bc946c-3f9e-48e9-98e6-f3bd37e25cc3" />

### Step 3: Review Alerts

The dashboard displays all detected threats with:

- **Timestamp**: When the attack was detected
- **Source IP**: Where the attack came from
- **URL**: The targeted endpoint
- **Attack Type**: Classification of the threat
- **Confidence**: How certain the system is (0-100%)
<img width="1696" height="868" alt="image" src="https://github.com/user-attachments/assets/b3c3f70c-94a5-4678-8d7b-5989fa00dcd1" />

### Step 4: Export Results

Click **"Export CSV"** to download a detailed report for:
- Security team review
- Compliance documentation
- Historical analysis
- Integration with SIEM tools
<img width="484" height="734" alt="image" src="https://github.com/user-attachments/assets/37989043-db17-46e7-abb0-892cbeb753d3" />

---
## Demo Video


https://github.com/user-attachments/assets/9eb01307-ea87-4121-ba1f-d1e8c0583d6e


## 📊 Understanding the Dashboard

### Alert Table Columns

| Column | Explanation |
|--------|-------------|
| **ID** | Unique identifier for each alert |
| **Time** | When the suspicious activity occurred |
| **Src IP** | The IP address that initiated the request |
| **URL** | The web address that was targeted |
| **Attack** | Type of attack detected |
| **Confidence** | Reliability score (higher = more certain) |

### Confidence Levels

- **80-100%**: High confidence - likely a real attack
- **60-79%**: Medium confidence - suspicious activity
- **40-59%**: Low confidence - potentially benign

---

## 🗂️ Project Structure

```
url-attack-detector/
├── app.py                  # Main application entry point
├── models.py              # Database schema for alerts
├── parser.py              # Parsers for PCAP and log files
├── detectors.py           # Attack detection algorithms
├── requirements.txt       # Python dependencies
├── Dockerfile             # Docker container configuration
├── docker-compose.yml     # Docker orchestration
├── templates/
│   └── index.html        # Web dashboard interface
├── static/
│   └── js/
│       └── app.js        # Frontend JavaScript
├── samples/
│   └── demo_access.log   # Sample log file for testing
├── uploads/              # Uploaded files storage
└── data/
    └── alerts.db         # SQLite database for alerts
```

---

## 🔧 Configuration

### Environment Variables

```bash
FLASK_ENV=development          # Set to 'production' for deployment
FLASK_APP=app.py              # Application entry point
TSHARK_PATH=/usr/bin/tshark   # Path to TShark binary
```

### Database Location

Alerts are stored in `data/alerts.db` (SQLite database). This file persists between restarts when using Docker volumes.

---

## 🧪 Testing with Sample Data

A sample access log is included for testing:

```bash
# Upload the sample file through the web interface
samples/demo_access.log
```

This sample contains examples of various attack types including SQL injection, XSS, directory traversal, and SSRF attempts.

---

## 🛠️ For Developers

### Adding New Detection Rules

1. Open `detectors.py`
2. Create a new detection function following this template:

```python
def detect_new_attack(params, raw):
    score = 0
    # Add your detection logic
    if suspicious_pattern_found:
        score += 50
    return (score >= threshold, score, 'Attack Name')
```

3. Add the function to `run_all()` function

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard homepage |
| `/upload` | POST | Upload and analyze files |
| `/alerts` | GET | Retrieve alerts as JSON |
| `/export` | GET | Export alerts (CSV/JSON) |

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Report Bugs**: Open an issue describing the problem
2. **Suggest Features**: Share your ideas for improvements
3. **Submit Pull Requests**: Fix bugs or add new features
4. **Improve Documentation**: Help make instructions clearer

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built for Smart India Hackathon (SIH)
- Powered by Flask, PyShark, and SQLAlchemy
- Detection algorithms based on OWASP Top 10 security risks

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/url-attack-detector/issues)
- **Documentation**: This README and inline code comments
- **Community**: Share your experiences and help others

---

## 🔒 Security Note

This tool is designed for **defensive security purposes only**. Use it to protect your own systems and authorized networks. Unauthorized use against third-party systems may be illegal.

---

**Made with ❤️ for a safer internet**
