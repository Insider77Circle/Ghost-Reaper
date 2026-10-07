# 🌐💻 MIRAGE — Cyberpunk Cyber Range

A honeypot that fights back with AI. MIRAGE simulates SSH, FTP, and HTTP/S
services behind a neon-soaked terminal UI, and uses Kimi AI to generate
realistic, stateful responses to whoever connects — EASY mode plays
vulnerable, HARD mode plays hardened. Built for red team practice and
security training.

```bash
git clone https://github.com/Insider77Circle/MIRAGE.git && cd MIRAGE
pip install -r requirements.txt
cp .env.example .env   # add your Kimi API key
sudo python3 mirage_v3_cyberpunk.py
```

Then: `ssh root@localhost -p 22` — and watch it lie to you beautifully.

## 🎯 What is Mirage V3?

**Mirage V3** is a cutting-edge cyber range simulator that combines **AI-powered response generation** with **stunning cyberpunk aesthetics**. Designed for safe red team practice and security education, it creates dynamic, realistic network responses using the Kimi AI API.

<div align="center">
<img src="docs/images/mirage-banner.png" alt="Mirage V3 Banner" width="800"/>
</div>

## ✨ Key Features

### 🤖 AI-Powered Intelligence
- **Dynamic Response Generation**: Kimi AI creates protocol-appropriate responses in real-time
- **Contextual Awareness**: Maintains state across connections and adapts behavior
- **Difficulty Modes**: EASY (vulnerable) vs HARD (security-conscious) responses
- **Burp Suite Integration**: Specialized handling for web vulnerability testing

### 🌐 Multi-Protocol Simulation
- **Port Coverage**: SSH (22), FTP (21), HTTP/HTTPS (80, 443, 8080)
- **Realistic Banners**: Convincing service responses for each protocol
- **Async Architecture**: Non-blocking I/O with asyncio for performance
- **State Management**: Global context maintains consistency across sessions

### 🎨 Immersive Cyberpunk Interface
- **Terminal TUI**: Rich-based live dashboard with neon aesthetics
- **Web Dashboard**: HTML5 interface with real-time updates
- **Live Metrics**: CPU, memory, threat level gauges with simulated data
- **Connection Monitoring**: Real-time connection history and AI activity logs

### 📊 Asset Fabrication
- **Fake Documents**: Generates Excel budgets and Word documents
- **Virtual File System**: Realistic file system with fabricated content
- **Dynamic Generation**: Creates assets based on context and interactions

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- sudo/admin privileges (for privileged ports)
- Kimi API key

### Installation

```bash
# Clone the repository
git clone https://github.com/Insider77Circle/MIRAGE.git
cd MIRAGE

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your Kimi API key

# Run with sudo (required for privileged ports)
sudo python3 mirage_v3_cyberpunk.py
```

## 📊 System Architecture

<div align="center">
<img src="docs/images/architecture-flowchart.png" alt="Mirage Architecture" width="600"/>
</div>

### Data Flow
1. **Network Connection** → Received on configured port
2. **Input Analysis** → Context prepared for AI processing  
3. **AI Generation** → Kimi API creates appropriate response
4. **Response Formatting** → Protocol-specific formatting applied
5. **Client Reply** → Dynamic response sent back
6. **UI Update** → Terminal and web interfaces updated

## 🎮 Usage Examples

### Basic Testing
```bash
# Test SSH service
ssh root@localhost -p 22

# Test web services
curl http://localhost:80
curl http://localhost:8080

# Test FTP service
ftp localhost 21
```

### Advanced Testing
```bash
# SQL Injection test (EASY mode)
curl -X POST http://localhost:8080/login -d "username=admin' OR 1=1--&password=test"

# Directory traversal test
curl http://localhost:8080/../../../etc/passwd

# XSS test
curl -X POST http://localhost:8080/search -d "q=<script>alert(1)</script>"
```

## 🛡️ Security Features

- **Safe Environment**: All responses are AI-generated, no real system access
- **Configurable Exposure**: Adjustable difficulty and response generation
- **Educational Purpose**: Designed for learning and authorized testing only
- **Isolated Operation**: Self-contained with no external dependencies beyond API

## 📈 Performance Metrics

<div align="center">
<img src="docs/images/performance-flowchart.png" alt="Performance Metrics" width="500"/>
</div>

- **Response Time**: < 2 seconds for AI-generated content
- **Concurrent Connections**: Handles multiple simultaneous clients
- **Memory Usage**: Efficient state management with circular buffers
- **CPU Simulation**: Dynamic load simulation for realistic metrics

## 🎨 Customization

### Changing Colors
```python
# Edit color constants in mirage_v3_cyberpunk.py
C_CB = "bright_cyan"      # Main borders
C_GN = "bright_green"     # Success/Go  
C_RD = "bright_red"       # Alerts/Errors
C_MG = "bright_magenta"   # Highlights
```

### Adding Vulnerabilities
Modify the `SYSTEM_PROMPT` in `mirage_core.py` to include new attack patterns and responses.

### Custom Assets
Extend the `Fabricator` class to generate additional file types and content.

## 🔍 Technical Specifications

### Core Components
- **MirageAI Class**: Handles AI communication and response generation
- **Fabricator Class**: Generates fake assets and documents
- **TUI System**: Rich-based terminal interface with live rendering
- **Async Server**: Multi-protocol network server with connection handling

### Dependencies
- `openai>=1.0.0` - AI client library
- `faker>=15.0.0` - Data generation
- `pandas>=1.5.0` - Data manipulation
- `python-docx>=0.8.11` - Document creation
- `rich>=13.0.0` - Terminal UI framework

## 📚 Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Detailed setup instructions
- **[API Reference](docs/API.md)** - Core classes and methods
- **[Architecture Guide](docs/ARCHITECTURE.md)** - System design and flow
- **[Customization Guide](docs/CUSTOMIZATION.md)** - How to modify and extend
- **[Security Guide](docs/SECURITY.md)** - Security considerations and best practices

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Ways to Contribute
- 🐛 Report bugs and issues
- 💡 Suggest new features and improvements
- 📝 Improve documentation
- 🎨 Create new themes and color schemes
- 🔧 Submit pull requests

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**IMPORTANT**: This tool is for educational and authorized testing purposes only. Always ensure you have permission before testing any systems. The authors are not responsible for misuse.

## 🙏 Acknowledgments

- **Kimi AI** for providing the powerful language model API
- **Rich Library** for the amazing terminal UI framework
- **Cyberpunk Community** for inspiration and aesthetic guidance
- **Security Researchers** who contribute to making the digital world safer

---

<div align="center">
<h3>🌟 Ready to dive into the cyberpunk matrix? </h3>
<p><strong>Mirage V3</strong> awaits your command.</p>
</div>

<div align="center">
<img src="docs/images/cyberpunk-matrix.gif" alt="Cyberpunk Matrix" width="400"/>
</div>
