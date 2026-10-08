#!/usr/bin/env python3
"""
PQScan Terminal Version - Post-Quantum Cryptography Scanner
A command-line interface with beautiful ASCII art and comprehensive scanning capabilities.
"""

import sys
import time
import socket
import ssl
import datetime
import json
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import ipaddress
from ascii_art import *

class PQScanTerminal:
    """Terminal-based PQScan implementation"""
    
    def __init__(self):
        self.scan_results = []
        self.verbose = False
        
    def display_banner(self, size="full"):
        """Display the appropriate banner based on terminal size"""
        try:
            import shutil
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 80
            
        if size == "full" and terminal_width >= 85:
            print(colored_banner())
        elif size == "compact" or (terminal_width >= 60 and terminal_width < 85):
            print(compact_banner())
        else:
            print(mini_banner())
            
    def show_help(self):
        """Display help information"""
        help_text = """
🔐 PQScan - Post-Quantum Cryptography Scanner

USAGE:
    python pqscan_terminal.py [OPTIONS] TARGET

TARGETS:
    192.168.1.1          Single IP address
    192.168.1.0/24       CIDR network range
    example.com          Domain name
    google.com,github.com Multiple comma-separated targets

OPTIONS:
    -p, --ports PORTS    Port specification (default: 443)
                         Examples: 443, 80,443,8443, 1-1024
    -v, --verbose        Enable verbose output
    -q, --quiet          Minimal output (results only)
    -o, --output FILE    Save results to JSON file
    -t, --timeout SEC    Connection timeout (default: 5)
    --no-banner          Skip banner display
    --format FORMAT      Output format: table, json, csv (default: table)
    --show-algorithms    Display PQC algorithm information
    --show-timeline      Display quantum threat timeline
    --show-matrix        Display security assessment matrix

EXAMPLES:
    python pqscan_terminal.py google.com
    python pqscan_terminal.py -p 80,443,8443 -v github.com
    python pqscan_terminal.py -p 1-1000 192.168.1.0/24
    python pqscan_terminal.py --output results.json example.com

For more information, visit: https://github.com/your-repo/pqscan
"""
        print(help_text)
        
    def parse_targets(self, target_string):
        """Parse target specification into list of hosts"""
        targets = []
        for target in target_string.split(','):
            target = target.strip()
            try:
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    targets.extend([str(ip) for ip in list(network.hosts())[:50]])  # Limit for demo
                else:
                    targets.append(target)
            except:
                targets.append(target)
        return targets
        
    def parse_ports(self, port_string):
        """Parse port specification into list of ports"""
        ports = []
        for port_spec in port_string.split(','):
            port_spec = port_spec.strip()
            if '-' in port_spec:
                start, end = map(int, port_spec.split('-'))
                ports.extend(range(start, min(end + 1, start + 100)))  # Limit range
            else:
                ports.append(int(port_spec))
        return ports[:50]  # Limit total ports
        
    def scan_host_port(self, host, port, timeout=5):
        """Scan a specific host:port combination"""
        try:
            if self.verbose:
                print(f"  🔍 Connecting to {host}:{port}...")
                
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der)
                    
                    result = {
                        "host": host,
                        "port": port,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "certificate": {
                            "subject": cert.subject.rfc4514_string(),
                            "issuer": cert.issuer.rfc4514_string(),
                            "not_valid_after": cert.not_valid_after.isoformat(),
                            "signature_algorithm": cert.signature_algorithm_oid._name
                        },
                        "pqc_analysis": self.analyze_pqc_readiness(cert),
                        "cipher_suite": self.get_cipher_info(ssock),
                        "scan_time": datetime.datetime.now().isoformat()
                    }
                    
                    if self.verbose:
                        status = "🟢 PQC Ready" if result["pqc_analysis"]["ready"] else "🔴 Vulnerable"
                        print(f"  ✅ {host}:{port} - {status}")
                        
                    return result
                    
        except socket.timeout:
            if self.verbose:
                print(f"  ⏰ Timeout: {host}:{port}")
        except ConnectionRefusedError:
            if self.verbose:
                print(f"  🚫 Connection refused: {host}:{port}")
        except Exception as e:
            if self.verbose:
                print(f"  ❌ Error scanning {host}:{port}: {str(e)}")
        return None
        
    def analyze_pqc_readiness(self, cert):
        """Analyze certificate for PQC readiness"""
        sig_alg = cert.signature_algorithm_oid._name.lower()
        
        # PQC algorithms
        pqc_algorithms = {
            'dilithium': {'ready': True, 'risk': 'LOW', 'action': 'Recommended'},
            'falcon': {'ready': True, 'risk': 'LOW', 'action': 'Recommended'},
            'sphincs': {'ready': True, 'risk': 'LOW', 'action': 'Conservative'},
            'kyber': {'ready': True, 'risk': 'LOW', 'action': 'Recommended'},
            'ntru': {'ready': True, 'risk': 'MEDIUM', 'action': 'Monitor'}
        }
        
        # Check for PQC algorithms
        for algo, props in pqc_algorithms.items():
            if algo in sig_alg:
                return {
                    "ready": True,
                    "algorithm": algo.title(),
                    "risk_level": props['risk'],
                    "action": props['action'],
                    "confidence": "High"
                }
                
        # Vulnerable algorithms
        if 'rsa' in sig_alg:
            if '4096' in sig_alg or 'rsa4096' in sig_alg:
                risk = "MEDIUM"
                action = "Plan Migration"
            elif '2048' in sig_alg or 'rsa2048' in sig_alg:
                risk = "HIGH"
                action = "Migrate Soon"
            else:
                risk = "CRITICAL"
                action = "Replace Now"
                
            return {
                "ready": False,
                "algorithm": "RSA",
                "risk_level": risk,
                "action": action,
                "confidence": "High"
            }
            
        elif 'ecdsa' in sig_alg or 'ec' in sig_alg:
            return {
                "ready": False,
                "algorithm": "ECDSA",
                "risk_level": "HIGH",
                "action": "Replace Soon",
                "confidence": "High"
            }
            
        elif 'dsa' in sig_alg:
            return {
                "ready": False,
                "algorithm": "DSA",
                "risk_level": "CRITICAL",
                "action": "Replace Now",
                "confidence": "High"
            }
            
        return {
            "ready": False,
            "algorithm": sig_alg,
            "risk_level": "UNKNOWN",
            "action": "Manual Review",
            "confidence": "Low"
        }
        
    def get_cipher_info(self, ssl_socket):
        """Get cipher suite information"""
        try:
            cipher = ssl_socket.cipher()
            return {
                "name": cipher[0] if cipher else "Unknown",
                "version": cipher[1] if cipher else "Unknown",
                "bits": cipher[2] if cipher else 0
            }
        except:
            return {"name": "Unknown", "version": "Unknown", "bits": 0}
            
    def display_progress(self, current, total, target=""):
        """Display progress with animation"""
        if not self.verbose:
            return
            
        bar = progress_bar(current, total, width=40)
        print(f"\r  {bar} Scanning {target}...", end='', flush=True)
        if current == total:
            print()  # New line when complete
            
    def scan_targets(self, targets, ports, timeout=5):
        """Scan all targets and ports"""
        print(f"\n🚀 Starting PQScan...")
        print(f"📍 Targets: {len(targets)}")
        print(f"🔌 Ports: {ports}")
        print(f"⏱️  Timeout: {timeout}s")
        print(f"{'─' * 50}")
        
        total_scans = len(targets) * len(ports)
        completed = 0
        
        for target in targets:
            if self.verbose:
                print(f"\n🎯 Scanning target: {target}")
                
            for port in ports:
                self.display_progress(completed, total_scans, f"{target}:{port}")
                
                result = self.scan_host_port(target, port, timeout)
                if result:
                    self.scan_results.append(result)
                    
                completed += 1
                time.sleep(0.1)  # Brief pause for visual effect
                
        if self.verbose:
            print(f"\n✅ Scan completed! Found {len(self.scan_results)} active services.")
        else:
            print(f"✅ Scan completed! Found {len(self.scan_results)} active services.")
            
    def display_results_table(self):
        """Display results in table format"""
        if not self.scan_results:
            print("\n❌ No active services found.")
            return
            
        print(scan_results_header())
        
        for result in self.scan_results:
            host = result["host"][:18]  # Truncate long hostnames
            port = str(result["port"])
            pqc = result["pqc_analysis"]
            
            # Status indicators
            status_icon = "🟢 Active"
            risk_color = {
                "LOW": "🟢",
                "MEDIUM": "🟡", 
                "HIGH": "🟠",
                "CRITICAL": "🔴",
                "UNKNOWN": "⚪"
            }.get(pqc["risk_level"], "⚪")
            
            algorithm = pqc["algorithm"][:14]  # Truncate long algorithm names
            risk = f"{risk_color} {pqc['risk_level']}"
            action = pqc["action"][:13]  # Truncate long actions
            
            # Format the row
            row = f"║  {host:<18}  {port:<6}  {status_icon:<10}  {algorithm:<14}  {risk:<8}  {action:<13}║"
            print(row)
            
        print(scan_results_footer())
        
    def display_results_json(self):
        """Display results in JSON format"""
        print(json.dumps(self.scan_results, indent=2))
        
    def save_results(self, filename):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump({
                    "scan_metadata": {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "total_results": len(self.scan_results),
                        "scanner_version": "PQScan v1.0.0"
                    },
                    "results": self.scan_results
                }, f, indent=2)
            print(f"💾 Results saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")
            
    def display_summary(self):
        """Display scan summary"""
        if not self.scan_results:
            return
            
        total = len(self.scan_results)
        ready_count = sum(1 for r in self.scan_results if r["pqc_analysis"]["ready"])
        vulnerable_count = total - ready_count
        
        risk_counts = {}
        for result in self.scan_results:
            risk = result["pqc_analysis"]["risk_level"]
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
        print(f"\n📊 Scan Summary:")
        print(f"   Total Services: {total}")
        print(f"   🟢 PQC Ready: {ready_count}")
        print(f"   🔴 Vulnerable: {vulnerable_count}")
        
        if risk_counts:
            print(f"\n🎯 Risk Breakdown:")
            for risk, count in sorted(risk_counts.items()):
                icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴", "UNKNOWN": "⚪"}.get(risk, "⚪")
                print(f"   {icon} {risk}: {count}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="PQScan - Post-Quantum Cryptography Scanner", 
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument("target", nargs='?', help="Target to scan (IP, domain, or CIDR)")
    parser.add_argument("-p", "--ports", default="443", help="Ports to scan (default: 443)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("--show-algorithms", action="store_true", help="Show PQC algorithms info")
    parser.add_argument("--show-timeline", action="store_true", help="Show quantum threat timeline")
    parser.add_argument("--show-matrix", action="store_true", help="Show security assessment matrix")
    
    args = parser.parse_args()
    
    scanner = PQScanTerminal()
    scanner.verbose = args.verbose and not args.quiet
    
    # Display banner unless suppressed
    if not args.no_banner and not args.quiet:
        scanner.display_banner()
        
    # Handle info displays
    if args.show_algorithms:
        print(algorithm_status())
        return
        
    if args.show_timeline:
        print(quantum_threat_timeline())
        return
        
    if args.show_matrix:
        print(security_matrix())
        return
        
    # Show help if no target provided
    if not args.target:
        scanner.show_help()
        return
        
    try:
        # Parse inputs
        targets = scanner.parse_targets(args.target)
        ports = scanner.parse_ports(args.ports)
        
        # Perform scan
        scanner.scan_targets(targets, ports, args.timeout)
        
        # Display results
        if args.format == "json":
            scanner.display_results_json()
        else:
            scanner.display_results_table()
            if not args.quiet:
                scanner.display_summary()
                
        # Save results if requested
        if args.output:
            scanner.save_results(args.output)
            
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()