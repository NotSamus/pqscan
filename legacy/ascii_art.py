#!/usr/bin/env python3
"""
ASCII Art for PQScan - Post-Quantum Cryptography Scanner
Beautiful terminal banners and visual elements
"""

import random
import time

def main_banner():
    """Main PQScan ASCII banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗                      ║
║    ██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║                      ║
║    ██████╔╝██║   ██║███████╗██║     ███████║██╔██╗ ██║                      ║
║    ██╔═══╝ ██║▄▄ ██║╚════██║██║     ██╔══██║██║╚██╗██║                      ║
║    ██║     ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║                      ║
║    ╚═╝      ╚══▀▀═╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                      ║
║                                                                               ║
║              🔐 Post-Quantum Cryptography Scanner 🔐                         ║
║                                                                               ║
║           ┌─────────────────────────────────────────────────────┐            ║
║           │  🛡️  Quantum-Safe Security Assessment Tool  🛡️   │            ║
║           │                                                     │            ║
║           │  ⚡ Fast Network Scanning                           │            ║
║           │  🔍 Certificate Analysis                            │            ║
║           │  🧮 Algorithm Detection                             │            ║
║           │  📊 Comprehensive Reporting                        │            ║
║           └─────────────────────────────────────────────────────┘            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
    return banner

def compact_banner():
    """Compact version for smaller terminals"""
    banner = """
┌─────────────────────────────────────────────────────────┐
│  ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗   │
│  ██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║   │
│  ██████╔╝██║   ██║███████╗██║     ███████║██╔██╗ ██║   │
│  ██╔═══╝ ██║▄▄ ██║╚════██║██║     ██╔══██║██║╚██╗██║   │
│  ██║     ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║   │
│  ╚═╝      ╚══▀▀═╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   │
│                                                         │
│        🔐 Post-Quantum Cryptography Scanner 🔐         │
│                                                         │
└─────────────────────────────────────────────────────────┘
"""
    return banner

def mini_banner():
    """Minimal banner for very compact displays"""
    banner = """
╔══════════════════════════════════════╗
║         🔐 PQScan v1.0.0 🔐          ║
║   Post-Quantum Cryptography Scanner  ║
╚══════════════════════════════════════╝
"""
    return banner

def quantum_circuit():
    """ASCII art representing a quantum circuit"""
    circuit = """
    Quantum Circuit Representation:
    
    |0⟩ ──[H]───●───[M]── Classical Bit 0
                  │    
    |0⟩ ──────────X───[M]── Classical Bit 1
    
    ┌─────────────────────────────────────┐
    │  Quantum Algorithms in Cryptography │
    │                                     │
    │  🔴 Shor's Algorithm (Factoring)    │
    │  🟡 Grover's Algorithm (Search)     │
    │  🟢 Post-Quantum Alternatives       │
    └─────────────────────────────────────┘
"""
    return circuit

def scanning_animation():
    """Animated scanning indicator"""
    frames = [
        "🔍 Scanning   ",
        "🔍 Scanning.  ",
        "🔍 Scanning.. ",
        "🔍 Scanning...",
        "🔍 Scanning.. ",
        "🔍 Scanning.  "
    ]
    return frames

def progress_bar(current, total, width=50):
    """Create an ASCII progress bar"""
    progress = current / total
    filled = int(width * progress)
    bar = "█" * filled + "░" * (width - filled)
    percentage = int(progress * 100)
    return f"[{bar}] {percentage}% ({current}/{total})"

def algorithm_status():
    """Display PQC algorithm status"""
    status = """
┌─────────────────────────────────────────────────────────────────┐
│                    🔐 PQC Algorithm Status 🔐                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Key Encapsulation Mechanisms (KEM):                           │
│  ✅ Kyber-512/768/1024    │ NIST Standard │ 🟢 High Security   │
│  ⚠️  NTRU                 │ Candidate     │ 🟡 Medium Security │
│  ⚠️  SABER                │ Candidate     │ 🟡 Medium Security │
│                                                                 │
│  Digital Signatures:                                           │
│  ✅ Dilithium-2/3/5      │ NIST Standard │ 🟢 High Security   │
│  ✅ Falcon-512/1024      │ NIST Standard │ 🟢 High Security   │
│  ✅ SPHINCS+-SHA2/SHAKE  │ NIST Standard │ 🔵 Conservative    │
│                                                                 │
│  Legacy (Quantum-Vulnerable):                                  │
│  ❌ RSA-2048/4096        │ Deprecated    │ 🔴 Vulnerable      │
│  ❌ ECDSA P-256/384      │ Deprecated    │ 🔴 Vulnerable      │
│  ❌ DSA                  │ Deprecated    │ 🔴 Critical        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
"""
    return status

def security_matrix():
    """Display security assessment matrix"""
    matrix = """
╔═══════════════════════════════════════════════════════════════════╗
║                      🛡️ Security Assessment Matrix 🛡️            ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  Risk Level │ Algorithm Type      │ Quantum Threat │ Action       ║
║  ───────────┼────────────────────┼────────────────┼──────────────║
║  🔴 CRITICAL│ DSA, weak RSA      │ Immediate      │ Replace Now  ║
║  🟠 HIGH    │ RSA-2048, ECDSA    │ 10-15 years    │ Plan Migration║
║  🟡 MEDIUM  │ RSA-4096, AES-128  │ 15-20 years    │ Monitor      ║
║  🟢 LOW     │ PQC Hybrid         │ Resistant      │ Recommended  ║
║  🔵 SECURE  │ Full PQC           │ Quantum-Safe   │ Future-Proof ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    return matrix

def scan_results_header():
    """Header for scan results"""
    header = """
╔════════════════════════════════════════════════════════════════════════════════╗
║                           📊 Scan Results Summary 📊                          ║
╠════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  Host                Port    Status      Algorithm        Risk    Action       ║
║  ──────────────────  ──────  ──────────  ──────────────  ──────  ─────────────║
"""
    return header

def scan_results_footer():
    """Footer for scan results"""
    footer = """║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
"""
    return footer

def quantum_threat_timeline():
    """Display quantum threat timeline"""
    timeline = """
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ⏰ Quantum Threat Timeline ⏰                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  2025 ████████████░░░░░░░░░░░░░░░░░░░░ Current Year                         │
│  2030 ████████████████████░░░░░░░░░░░░ Small-scale quantum computers       │
│  2035 ██████████████████████████████░░ Cryptographically relevant QC       │
│  2040 ████████████████████████████████ Full quantum threat realized        │
│                                                                             │
│  🔴 Immediate Risk: DSA, weak RSA (<2048)                                  │
│  🟠 Short-term Risk: RSA-2048, ECDSA P-256                                 │
│  🟡 Medium-term Risk: RSA-4096, ECDSA P-384                                │
│  🟢 Quantum-Safe: PQC algorithms (Kyber, Dilithium, etc.)                  │
│                                                                             │
│  📅 Recommended Migration Start: NOW                                       │
│  📅 Target Completion: 2030                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
"""
    return timeline

def network_topology():
    """ASCII network topology diagram"""
    topology = """
    Network Topology Scan:
    
         ┌─────────┐
         │Internet │
         │Gateway  │
         └────┬────┘
              │
      ┌───────┴───────┐
      │   Firewall    │
      │  🛡️ PQScan   │
      └───────┬───────┘
              │
    ┌─────────┴─────────┐
    │    Core Switch    │
    └─┬─────────────┬───┘
      │             │
  ┌───┴───┐     ┌───┴────┐
  │Server │     │Endpoint│
  │Subnet │     │Devices │
  │🔒     │     │📱💻🖥️ │
  └───────┘     └────────┘
"""
    return topology

def certificate_chain():
    """ASCII certificate chain visualization"""
    chain = """
    Certificate Chain Analysis:
    
    ┌─────────────────────────┐
    │     Root CA             │
    │  🏛️ Trust Anchor       │
    │  Algorithm: RSA-4096    │
    │  Status: ⚠️ Vulnerable  │
    └──────────┬──────────────┘
               │ signs
               ▼
    ┌─────────────────────────┐
    │  Intermediate CA        │
    │  🔗 Chain Link          │
    │  Algorithm: ECDSA-384   │
    │  Status: 🟠 At Risk     │
    └──────────┬──────────────┘
               │ signs
               ▼
    ┌─────────────────────────┐
    │   End Entity Cert       │
    │  🌐 Server Certificate  │
    │  Algorithm: RSA-2048    │
    │  Status: 🔴 High Risk   │
    └─────────────────────────┘
"""
    return chain

def colored_banner():
    """Banner with color codes (for terminals that support colors)"""
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m',
        'underline': '\033[4m',
        'end': '\033[0m'
    }
    
    banner = f"""
{colors['cyan']}{colors['bold']}╔═══════════════════════════════════════════════════════════════════════════════╗{colors['end']}
{colors['cyan']}║                                                                               ║{colors['end']}
{colors['blue']}{colors['bold']}║    ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗                      ║{colors['end']}
{colors['blue']}║    ██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║                      ║{colors['end']}
{colors['blue']}║    ██████╔╝██║   ██║███████╗██║     ███████║██╔██╗ ██║                      ║{colors['end']}
{colors['blue']}║    ██╔═══╝ ██║▄▄ ██║╚════██║██║     ██╔══██║██║╚██╗██║                      ║{colors['end']}
{colors['blue']}║    ██║     ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║                      ║{colors['end']}
{colors['blue']}║    ╚═╝      ╚══▀▀═╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                      ║{colors['end']}
{colors['cyan']}║                                                                               ║{colors['end']}
{colors['yellow']}{colors['bold']}║              🔐 Post-Quantum Cryptography Scanner 🔐                         ║{colors['end']}
{colors['cyan']}║                                                                               ║{colors['end']}
{colors['green']}║           ┌─────────────────────────────────────────────────────┐            ║{colors['end']}
{colors['green']}║           │  🛡️  Quantum-Safe Security Assessment Tool  🛡️   │            ║{colors['end']}
{colors['green']}║           │                                                     │            ║{colors['end']}
{colors['white']}║           │  ⚡ Fast Network Scanning                           │            ║{colors['end']}
{colors['white']}║           │  🔍 Certificate Analysis                            │            ║{colors['end']}
{colors['white']}║           │  🧮 Algorithm Detection                             │            ║{colors['end']}
{colors['white']}║           │  📊 Comprehensive Reporting                        │            ║{colors['end']}
{colors['green']}║           └─────────────────────────────────────────────────────┘            ║{colors['end']}
{colors['cyan']}║                                                                               ║{colors['end']}
{colors['cyan']}{colors['bold']}╚═══════════════════════════════════════════════════════════════════════════════╝{colors['end']}
"""
    return banner

def simple_logo():
    """Simple PQScan logo for inline use"""
    return "🔐 PQScan"

def animated_typing_effect(text, delay=0.05):
    """Create typing animation effect"""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def demo_all():
    """Demonstrate all ASCII art"""
    print("=== PQScan ASCII Art Collection ===\n")
    
    print("1. Main Banner:")
    print(main_banner())
    
    print("\n2. Compact Banner:")
    print(compact_banner())
    
    print("\n3. Mini Banner:")
    print(mini_banner())
    
    print("\n4. Algorithm Status:")
    print(algorithm_status())
    
    print("\n5. Security Matrix:")
    print(security_matrix())
    
    print("\n6. Quantum Threat Timeline:")
    print(quantum_threat_timeline())
    
    print("\n7. Progress Bar Example:")
    for i in range(0, 101, 10):
        print(f"\r{progress_bar(i, 100)}", end='', flush=True)
        time.sleep(0.1)
    print("\n")
    
    print("\n8. Scan Results Example:")
    print(scan_results_header())
    print("║  google.com          443     🟢 Active   RSA-2048        🟠 HIGH  Plan Migration║")
    print("║  github.com          443     🟢 Active   ECDSA-256       🔴 CRIT  Replace Now  ║")
    print("║  quantum-safe.com    443     🟢 Active   Kyber-768       🟢 LOW   Recommended  ║")
    print(scan_results_footer())

if __name__ == "__main__":
    demo_all()