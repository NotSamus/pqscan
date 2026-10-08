# 🔐 PQScan - Post-Quantum Cryptography Scanner

A beautiful and lightweight Post-Quantum Cryptography (PQC) scanner designed to evaluate and demonstrate the impact of quantum-safe algorithms in small, resource-constrained environments.

![PQScan Interface](https://img.shields.io/badge/Interface-Modern%20UI-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

### 🎨 Beautiful Modern UI

- **Dark/Light Theme Support** - Toggle between themes with a single click
- **Responsive Design** - Adapts to different screen sizes
- **Tabbed Interface** - Organized workflow with dedicated sections
- **Real-time Progress** - Live scan progress and status updates
- **Professional Styling** - Modern CustomTkinter-based interface

### 🔍 Advanced Scanning Capabilities

- **Multi-target Support** - Scan IP ranges, individual hosts, or domain names
- **Flexible Port Configuration** - Custom port ranges and individual ports
- **Certificate Analysis** - Deep SSL/TLS certificate examination
- **Cipher Suite Enumeration** - Comprehensive cipher analysis
- **PQC Readiness Assessment** - Evaluate quantum-safe algorithm support

### 📊 Comprehensive Results

- **Interactive Results Table** - Sortable and filterable scan results
- **Visual Analytics** - Charts and graphs for scan data
- **Export Options** - JSON, CSV, and PDF report generation
- **Real-time Updates** - Live scanning feedback and progress

### 🔐 PQC Algorithm Database

- **Algorithm Information** - Detailed specs for major PQC algorithms
- **Standardization Status** - Track NIST standardization progress
- **Performance Metrics** - Compare algorithm characteristics
- **Recommendations** - Migration guidance and best practices

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- macOS, Windows, or Linux

### Installation

1. **Clone or download the project:**

   ```bash
   git clone <repository-url>
   cd pqscan
   ```

2. **Set up virtual environment (recommended):**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**

   ```bash
   pip install customtkinter tkinter-tooltip pillow matplotlib seaborn pandas numpy cryptography pycryptodome requests beautifulsoup4
   ```

4. **Run the application:**
   ```bash
   python main.py
   ```

### Testing Installation

Run the test script to verify everything is working:

```bash
python test_pqscan.py
```

## 📖 How to Use

### 1. Configure Your Scan

- **Target**: Enter IP addresses, CIDR ranges, or domain names
  - Examples: `192.168.1.1`, `10.0.0.0/24`, `example.com`
- **Ports**: Specify ports to scan
  - Examples: `443`, `443,8443,9443`, `1-1024`
- **Options**: Choose scan depth and features

### 2. Run the Scan

- Click **🚀 Start Scan** to begin
- Monitor real-time progress and output
- View live scanning status and discovered services

### 3. Analyze Results

- Switch to the **📊 Results** tab
- Review the summary and detailed findings
- Examine PQC readiness assessments
- Check vulnerability reports

### 4. Export Reports

- Go to the **📄 Reports** tab
- Choose your preferred format (JSON, CSV, PDF)
- Generate comprehensive reports for stakeholders

## 🔐 Supported PQC Algorithms

### Key Encapsulation Mechanisms (KEM)

- **Kyber** - NIST standardized, high performance
- **NTRU** - Established lattice-based algorithm
- **SABER** - Fast and efficient
- **FrodoKEM** - Conservative security approach

### Digital Signatures

- **Dilithium** - NIST standardized, versatile
- **Falcon** - Compact signatures
- **SPHINCS+** - Hash-based, conservative security
- **Rainbow** - Multivariate approach

## 🏗️ Architecture

### Core Components

- **Scanner Engine** - Multi-threaded scanning capability
- **Certificate Analyzer** - X.509 certificate parsing and analysis
- **PQC Detector** - Algorithm identification and assessment
- **Results Manager** - Data storage and export functionality
- **UI Framework** - Modern CustomTkinter interface

### Technical Stack

- **Frontend**: CustomTkinter (Modern UI framework)
- **Networking**: Python sockets, SSL/TLS
- **Cryptography**: Python cryptography library
- **Data Analysis**: Pandas, NumPy
- **Visualization**: Matplotlib, Seaborn
- **Export**: JSON, CSV, PDF support

## 🛠️ Configuration

### Scan Options

- **Deep Certificate Analysis**: Detailed certificate examination
- **Cipher Suite Enumeration**: Comprehensive cipher analysis
- **PQC Vulnerability Assessment**: Security evaluation

### Theme Customization

- **Dark Mode**: Default professional dark theme
- **Light Mode**: Clean light theme option
- **Custom Colors**: Blue, green, and dark-blue themes

## 📋 Sample Targets for Testing

### Local Network Testing

```
192.168.1.0/24        # Scan entire local subnet
10.0.0.1-10.0.0.100   # Scan range of IPs
localhost:8443        # Test local SSL service
```

### Public Service Testing

```
google.com            # Major websites
github.com            # Code repositories
cloudflare.com        # CDN services
```

### IoT Device Testing

```
192.168.1.100:443     # Smart home devices
10.0.1.50:8443        # Industrial IoT
172.16.0.0/24         # Private network devices
```

## 🔍 Understanding Results

### PQC Readiness Indicators

- **✅ Ready**: Service supports post-quantum algorithms
- **❌ Not Ready**: Service uses quantum-vulnerable algorithms
- **⚠️ Unknown**: Manual review required

### Risk Assessment

- **High Risk**: RSA, ECDSA with small key sizes
- **Medium Risk**: Large key classical algorithms
- **Low Risk**: Hybrid classical/PQC implementations
- **Secure**: Full PQC algorithm support

## 🚀 Future Enhancements

### Planned Features

- **Cloud Integration** - Azure, AWS, GCP scanning
- **API Support** - REST API for automation
- **Custom Plugins** - Extensible architecture
- **Advanced Analytics** - ML-powered insights
- **Team Collaboration** - Multi-user support

### Roadmap

- [ ] Network discovery automation
- [ ] Integration with security frameworks
- [ ] Mobile companion app
- [ ] Enterprise dashboard
- [ ] Compliance reporting

## 🤝 Contributing

We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest features.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

## 🙏 Acknowledgments

- **NIST** - Post-Quantum Cryptography Standardization
- **CustomTkinter** - Modern UI framework
- **Python Cryptography** - Excellent crypto library
- **Open Source Community** - Invaluable tools and libraries

## 📞 Support

For questions, issues, or feature requests:

- Create an issue on GitHub
- Contact the development team
- Check the documentation wiki

---

**PQScan** - Preparing your infrastructure for the quantum age, one scan at a time. 🚀
