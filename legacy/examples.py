#!/usr/bin/env python3
"""
PQScan Usage Examples and Demonstrations
Shows how to use both the terminal and GUI versions effectively.
"""

def show_examples():
    """Display usage examples for PQScan"""
    
    examples = """
🔐 PQScan Usage Examples 🔐
═══════════════════════════════════════════════════════════════════════

🎯 BASIC SCANNING EXAMPLES:

1. Single Host Scan:
   python pqscan_terminal.py google.com
   python pqscan_terminal.py github.com

2. Multiple Hosts:
   python pqscan_terminal.py google.com,github.com,microsoft.com

3. Network Range Scan:
   python pqscan_terminal.py 192.168.1.0/24
   python pqscan_terminal.py 10.0.0.1-10.0.0.50

4. Custom Port Scanning:
   python pqscan_terminal.py -p 80,443,8443 example.com
   python pqscan_terminal.py -p 1-1000 localhost

🔍 ADVANCED SCANNING OPTIONS:

5. Verbose Output:
   python pqscan_terminal.py -v google.com
   
6. Multiple Ports with Verbose:
   python pqscan_terminal.py -v -p 443,8443,9443 github.com

7. Save Results to File:
   python pqscan_terminal.py -o scan_results.json google.com
   python pqscan_terminal.py -v -o detailed_scan.json -p 80,443 example.com

8. JSON Output Format:
   python pqscan_terminal.py --format json google.com

9. Quiet Mode (Results Only):
   python pqscan_terminal.py -q google.com

📊 INFORMATION DISPLAYS:

10. Show PQC Algorithm Information:
    python pqscan_terminal.py --show-algorithms

11. Display Quantum Threat Timeline:
    python pqscan_terminal.py --show-timeline

12. Security Assessment Matrix:
    python pqscan_terminal.py --show-matrix

🎨 DISPLAY OPTIONS:

13. No Banner (Clean Output):
    python pqscan_terminal.py --no-banner google.com

14. Custom Timeout:
    python pqscan_terminal.py -t 10 slow-server.com

🖥️  GUI VERSION:

15. Launch Graphical Interface:
    python main.py

═══════════════════════════════════════════════════════════════════════

📋 REAL-WORLD SCANNING SCENARIOS:

🏢 Enterprise Network Assessment:
   python pqscan_terminal.py -v -p 443,8443 -o enterprise_scan.json 10.0.0.0/24

🌐 Public Website Security Check:
   python pqscan_terminal.py -v google.com,facebook.com,amazon.com,microsoft.com

🔒 SSL/TLS Infrastructure Audit:
   python pqscan_terminal.py -p 443,8443,9443 -o ssl_audit.json company.com

🏠 Home Network Security:
   python pqscan_terminal.py -v 192.168.1.0/24

☁️  Cloud Service Assessment:
   python pqscan_terminal.py -v -p 443 aws.amazon.com,azure.microsoft.com,cloud.google.com

═══════════════════════════════════════════════════════════════════════

🎯 INTERPRETING RESULTS:

Risk Levels:
🔴 CRITICAL - Immediate action required (DSA, weak RSA)
🟠 HIGH     - Plan migration within 2-3 years (RSA-2048, ECDSA)
🟡 MEDIUM   - Monitor and plan for future (RSA-4096)
🟢 LOW      - Hybrid PQC implementations
🔵 SECURE   - Full post-quantum algorithms

Actions:
Replace Now    - Critical vulnerabilities, immediate replacement
Migrate Soon   - High risk, start planning migration
Plan Migration - Medium-term planning required
Monitor        - Keep track of developments
Recommended    - Good security posture

═══════════════════════════════════════════════════════════════════════

🚀 PERFORMANCE TIPS:

• Use specific port ranges instead of scanning all ports
• Limit network scans to reasonable ranges (avoid /8 networks)
• Use verbose mode (-v) for detailed analysis
• Save results (-o) for later analysis and reporting
• Use quiet mode (-q) for automated scripts

🔧 TROUBLESHOOTING:

• Connection timeouts: Increase timeout with -t option
• Permission denied: May need elevated privileges for some scans
• Network unreachable: Check network connectivity and firewall rules
• Certificate errors: Some servers may have invalid certificates

═══════════════════════════════════════════════════════════════════════
"""
    
    print(examples)

def demo_commands():
    """Show interactive demo of commands"""
    import time
    
    print("🎭 PQScan Interactive Demo")
    print("=" * 50)
    
    commands = [
        "python pqscan_terminal.py --show-algorithms",
        "python pqscan_terminal.py --show-timeline", 
        "python pqscan_terminal.py --show-matrix",
        "python pqscan_terminal.py -v google.com",
        "python pqscan_terminal.py --format json github.com"
    ]
    
    for i, cmd in enumerate(commands, 1):
        print(f"\n{i}. {cmd}")
        print("-" * len(cmd))
        time.sleep(1)
        
    print(f"\n🎯 Try any of these commands to explore PQScan!")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo_commands()
    else:
        show_examples()