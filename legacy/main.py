#!/usr/bin/env python3
"""
PQScan - Post-Quantum Cryptography Scanner
A lightweight tool for evaluating quantum-safe algorithms in resource-constrained environments.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import csv
import datetime
import socket
import ssl
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkinter
import seaborn as sns
from typing import Dict, List, Any
import time
import ipaddress
import os

# Configure customtkinter theme
ctk.set_appearance_mode("dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class PQScanApp:
    """Main application class for PQScan GUI"""
    
    def __init__(self):
        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("PQScan - Post-Quantum Cryptography Scanner")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Configure grid weights for responsive design
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        # Application state
        self.scan_results = []
        self.scan_in_progress = False
        self.current_theme = "dark"
        
        # PQC algorithms database
        self.pqc_algorithms = {
            "KEM": {
                "Kyber": {"strength": "High", "performance": "Fast", "standardized": True},
                "NTRU": {"strength": "High", "performance": "Medium", "standardized": False},
                "SABER": {"strength": "High", "performance": "Fast", "standardized": False},
                "FrodoKEM": {"strength": "Very High", "performance": "Slow", "standardized": False}
            },
            "Digital Signatures": {
                "Dilithium": {"strength": "High", "performance": "Fast", "standardized": True},
                "Falcon": {"strength": "High", "performance": "Medium", "standardized": True},
                "SPHINCS+": {"strength": "Very High", "performance": "Slow", "standardized": True},
                "Rainbow": {"strength": "Medium", "performance": "Fast", "standardized": False}
            }
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the complete user interface"""
        self.create_header()
        self.create_main_content()
        self.create_status_bar()
        
    def create_header(self):
        """Create the application header with branding and controls"""
        header_frame = ctk.CTkFrame(self.root, height=100, corner_radius=0)
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_columnconfigure(1, weight=1)
        header_frame.grid_propagate(False)
        
        # Logo and title section
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="w", padx=20, pady=15)
        
        # Main title
        title_label = ctk.CTkLabel(
            title_frame, 
            text="🔐 PQScan", 
            font=ctk.CTkFont(size=32, weight="bold")
        )
        title_label.grid(row=0, column=0, sticky="w")
        
        # Subtitle
        subtitle_label = ctk.CTkLabel(
            title_frame, 
            text="Post-Quantum Cryptography Scanner", 
            font=ctk.CTkFont(size=14),
            text_color=("gray60", "gray40")
        )
        subtitle_label.grid(row=1, column=0, sticky="w", pady=(0, 5))
        
        # Control buttons
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.grid(row=0, column=2, sticky="e", padx=20, pady=15)
        
        # Theme toggle button
        self.theme_button = ctk.CTkButton(
            controls_frame,
            text="☀️ Light",
            width=100,
            height=32,
            command=self.toggle_theme
        )
        self.theme_button.grid(row=0, column=0, padx=(0, 10))
        
        # Settings button
        settings_button = ctk.CTkButton(
            controls_frame,
            text="⚙️ Settings",
            width=100,
            height=32,
            command=self.open_settings
        )
        settings_button.grid(row=0, column=1, padx=(0, 10))
        
        # Help button
        help_button = ctk.CTkButton(
            controls_frame,
            text="❓ Help",
            width=80,
            height=32,
            command=self.show_help
        )
        help_button.grid(row=0, column=2)
        
    def create_main_content(self):
        """Create the main content area with tabs"""
        # Main container
        main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(10, 20))
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)
        
        # Create tabview
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        
        # Add tabs
        self.tab_scanner = self.tabview.add("🔍 Scanner")
        self.tab_results = self.tabview.add("📊 Results")
        self.tab_algorithms = self.tabview.add("🔐 Algorithms")
        self.tab_reports = self.tabview.add("📄 Reports")
        
        # Configure tab content
        self.setup_scanner_tab()
        self.setup_results_tab()
        self.setup_algorithms_tab()
        self.setup_reports_tab()
        
    def setup_scanner_tab(self):
        """Setup the main scanner interface"""
        # Configure grid
        self.tab_scanner.grid_columnconfigure(1, weight=1)
        self.tab_scanner.grid_rowconfigure(1, weight=1)
        
        # Left panel - Configuration
        config_frame = ctk.CTkFrame(self.tab_scanner, width=400)
        config_frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 10), pady=0)
        config_frame.grid_propagate(False)
        config_frame.grid_columnconfigure(0, weight=1)
        
        # Configuration header
        config_header = ctk.CTkLabel(
            config_frame, 
            text="Scan Configuration", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        config_header.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="w")
        
        # Target configuration
        target_frame = ctk.CTkFrame(config_frame)
        target_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        target_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(target_frame, text="Target:", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=(15, 5)
        )
        
        self.target_entry = ctk.CTkEntry(
            target_frame, 
            placeholder_text="192.168.1.0/24, example.com, or specific IP",
            height=35
        )
        self.target_entry.grid(row=1, column=0, columnspan=2, sticky="ew", padx=15, pady=(0, 15))
        
        # Port configuration
        port_frame = ctk.CTkFrame(config_frame)
        port_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))
        port_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(port_frame, text="Ports:", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=(15, 5)
        )
        
        self.port_entry = ctk.CTkEntry(
            port_frame, 
            placeholder_text="443,8443,9443 or 1-1024",
            height=35
        )
        self.port_entry.grid(row=1, column=0, columnspan=2, sticky="ew", padx=15, pady=(0, 15))
        
        # Scan options
        options_frame = ctk.CTkFrame(config_frame)
        options_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 15))
        options_frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(options_frame, text="Scan Options:", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=(15, 10)
        )
        
        # Checkboxes for scan options
        self.deep_scan_var = ctk.BooleanVar(value=True)
        deep_scan_cb = ctk.CTkCheckBox(
            options_frame, 
            text="Deep Certificate Analysis", 
            variable=self.deep_scan_var
        )
        deep_scan_cb.grid(row=1, column=0, sticky="w", padx=15, pady=2)
        
        self.cipher_scan_var = ctk.BooleanVar(value=True)
        cipher_scan_cb = ctk.CTkCheckBox(
            options_frame, 
            text="Cipher Suite Enumeration", 
            variable=self.cipher_scan_var
        )
        cipher_scan_cb.grid(row=2, column=0, sticky="w", padx=15, pady=2)
        
        self.vulnerability_scan_var = ctk.BooleanVar(value=False)
        vuln_scan_cb = ctk.CTkCheckBox(
            options_frame, 
            text="PQC Vulnerability Assessment", 
            variable=self.vulnerability_scan_var
        )
        vuln_scan_cb.grid(row=3, column=0, sticky="w", padx=15, pady=(2, 15))
        
        # Scan button
        self.scan_button = ctk.CTkButton(
            config_frame,
            text="🚀 Start Scan",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.start_scan
        )
        self.scan_button.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 20))
        
        # Right panel - Live output and progress
        output_frame = ctk.CTkFrame(self.tab_scanner)
        output_frame.grid(row=0, column=1, sticky="ew", padx=0, pady=0)
        output_frame.grid_columnconfigure(0, weight=1)
        
        # Progress section
        progress_label = ctk.CTkLabel(
            output_frame, 
            text="Scan Progress", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        progress_label.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="w")
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(output_frame)
        self.progress_bar.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        self.progress_bar.set(0)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            output_frame, 
            text="Ready to scan",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=2, column=0, pady=(0, 20), padx=20, sticky="w")
        
        # Live output area
        output_container = ctk.CTkFrame(self.tab_scanner)
        output_container.grid(row=1, column=1, sticky="nsew", padx=0, pady=(10, 0))
        output_container.grid_columnconfigure(0, weight=1)
        output_container.grid_rowconfigure(1, weight=1)
        
        output_header = ctk.CTkLabel(
            output_container, 
            text="Live Output", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        output_header.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="w")
        
        # Create text widget for output
        self.output_text = ctk.CTkTextbox(output_container, height=400)
        self.output_text.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        
    def setup_results_tab(self):
        """Setup the results visualization tab"""
        self.tab_results.grid_columnconfigure(0, weight=1)
        self.tab_results.grid_rowconfigure(1, weight=1)
        
        # Results header
        results_header = ctk.CTkLabel(
            self.tab_results, 
            text="Scan Results & Analysis", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        results_header.grid(row=0, column=0, pady=20, padx=20, sticky="w")
        
        # Results container
        results_container = ctk.CTkFrame(self.tab_results)
        results_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        results_container.grid_columnconfigure(0, weight=1)
        results_container.grid_rowconfigure(0, weight=1)
        
        # Create notebook for different result views
        self.results_notebook = ttk.Notebook(results_container)
        self.results_notebook.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.summary_frame, text="📋 Summary")
        
        # Detailed results tab
        self.detailed_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.detailed_frame, text="🔍 Detailed")
        
        # Visualization tab
        self.viz_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.viz_frame, text="📈 Charts")
        
        self.setup_results_content()
        
    def setup_results_content(self):
        """Setup the content for results tabs"""
        # Summary tab content
        summary_text = ctk.CTkTextbox(self.summary_frame, height=400)
        summary_text.pack(fill="both", expand=True, padx=10, pady=10)
        summary_text.insert("0.0", "No scan results available yet. Run a scan to see results here.")
        
        # Detailed results with treeview
        tree_frame = tk.Frame(self.detailed_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create treeview for detailed results
        columns = ("Host", "Port", "PQC Support", "Algorithms", "Status")
        self.results_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def setup_algorithms_tab(self):
        """Setup the PQC algorithms information tab"""
        self.tab_algorithms.grid_columnconfigure(0, weight=1)
        self.tab_algorithms.grid_rowconfigure(1, weight=1)
        
        # Algorithms header
        algo_header = ctk.CTkLabel(
            self.tab_algorithms, 
            text="Post-Quantum Cryptography Algorithms", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        algo_header.grid(row=0, column=0, pady=20, padx=20, sticky="w")
        
        # Algorithms content
        algo_container = ctk.CTkScrollableFrame(self.tab_algorithms)
        algo_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        algo_container.grid_columnconfigure(0, weight=1)
        
        self.create_algorithm_cards(algo_container)
        
    def create_algorithm_cards(self, parent):
        """Create information cards for PQC algorithms"""
        row = 0
        for category, algorithms in self.pqc_algorithms.items():
            # Category header
            category_label = ctk.CTkLabel(
                parent, 
                text=f"{category}", 
                font=ctk.CTkFont(size=18, weight="bold")
            )
            category_label.grid(row=row, column=0, sticky="w", pady=(20, 10), padx=20)
            row += 1
            
            for algo_name, details in algorithms.items():
                # Algorithm card
                card_frame = ctk.CTkFrame(parent)
                card_frame.grid(row=row, column=0, sticky="ew", padx=20, pady=5)
                card_frame.grid_columnconfigure(1, weight=1)
                
                # Algorithm name
                name_label = ctk.CTkLabel(
                    card_frame, 
                    text=algo_name, 
                    font=ctk.CTkFont(size=14, weight="bold")
                )
                name_label.grid(row=0, column=0, sticky="w", padx=15, pady=10)
                
                # Algorithm details
                details_text = f"Strength: {details['strength']} | Performance: {details['performance']} | Standardized: {'Yes' if details['standardized'] else 'No'}"
                details_label = ctk.CTkLabel(
                    card_frame, 
                    text=details_text, 
                    font=ctk.CTkFont(size=11),
                    text_color=("gray60", "gray40")
                )
                details_label.grid(row=0, column=1, sticky="e", padx=15, pady=10)
                
                row += 1
                
    def setup_reports_tab(self):
        """Setup the reports and export tab"""
        self.tab_reports.grid_columnconfigure(0, weight=1)
        self.tab_reports.grid_rowconfigure(1, weight=1)
        
        # Reports header
        reports_header = ctk.CTkLabel(
            self.tab_reports, 
            text="Reports & Export", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        reports_header.grid(row=0, column=0, pady=20, padx=20, sticky="w")
        
        # Reports content
        reports_container = ctk.CTkFrame(self.tab_reports)
        reports_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        reports_container.grid_columnconfigure(1, weight=1)
        
        # Export options
        export_frame = ctk.CTkFrame(reports_container, width=300)
        export_frame.grid(row=0, column=0, sticky="nsew", padx=(20, 10), pady=20)
        export_frame.grid_propagate(False)
        
        export_label = ctk.CTkLabel(
            export_frame, 
            text="Export Options", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        export_label.grid(row=0, column=0, pady=(20, 15), padx=20, sticky="w")
        
        # Export buttons
        export_json_btn = ctk.CTkButton(
            export_frame,
            text="📄 Export as JSON",
            command=lambda: self.export_results("json")
        )
        export_json_btn.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        
        export_csv_btn = ctk.CTkButton(
            export_frame,
            text="📊 Export as CSV",
            command=lambda: self.export_results("csv")
        )
        export_csv_btn.grid(row=2, column=0, sticky="ew", padx=20, pady=5)
        
        export_pdf_btn = ctk.CTkButton(
            export_frame,
            text="📑 Generate PDF Report",
            command=lambda: self.export_results("pdf")
        )
        export_pdf_btn.grid(row=3, column=0, sticky="ew", padx=20, pady=(5, 20))
        
        # Report preview
        preview_frame = ctk.CTkFrame(reports_container)
        preview_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 20), pady=20)
        preview_frame.grid_columnconfigure(0, weight=1)
        preview_frame.grid_rowconfigure(1, weight=1)
        
        preview_label = ctk.CTkLabel(
            preview_frame, 
            text="Report Preview", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        preview_label.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="w")
        
        self.report_preview = ctk.CTkTextbox(preview_frame)
        self.report_preview.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        
    def create_status_bar(self):
        """Create the status bar at the bottom"""
        status_frame = ctk.CTkFrame(self.root, height=30, corner_radius=0)
        status_frame.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        status_frame.grid_columnconfigure(1, weight=1)
        status_frame.grid_propagate(False)
        
        # Version info
        version_label = ctk.CTkLabel(
            status_frame, 
            text="PQScan v1.0.0", 
            font=ctk.CTkFont(size=10)
        )
        version_label.grid(row=0, column=0, padx=20, pady=5, sticky="w")
        
        # Connection status
        self.connection_status = ctk.CTkLabel(
            status_frame, 
            text="● Ready", 
            font=ctk.CTkFont(size=10),
            text_color="green"
        )
        self.connection_status.grid(row=0, column=2, padx=20, pady=5, sticky="e")
        
    # Event handlers and utility methods
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        if self.current_theme == "dark":
            ctk.set_appearance_mode("light")
            self.theme_button.configure(text="🌙 Dark")
            self.current_theme = "light"
        else:
            ctk.set_appearance_mode("dark")
            self.theme_button.configure(text="☀️ Light")
            self.current_theme = "dark"
            
    def open_settings(self):
        """Open settings dialog"""
        messagebox.showinfo("Settings", "Settings panel coming soon!")
        
    def show_help(self):
        """Show help dialog"""
        help_text = """
PQScan - Post-Quantum Cryptography Scanner

This tool helps you evaluate the quantum-readiness of your network infrastructure.

How to use:
1. Enter target hosts (IP addresses, ranges, or domain names)
2. Specify ports to scan (default SSL/TLS ports recommended)
3. Choose scan options based on your needs
4. Click 'Start Scan' to begin analysis
5. Review results in the Results tab
6. Export findings using the Reports tab

For detailed documentation, visit: https://github.com/your-repo/pqscan
        """
        messagebox.showinfo("Help", help_text)
        
    def start_scan(self):
        """Start the PQC scanning process"""
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "A scan is already running. Please wait for it to complete.")
            return
            
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Invalid Target", "Please enter a target to scan.")
            return
            
        # Start scan in separate thread
        self.scan_in_progress = True
        self.scan_button.configure(text="⏹️ Stop Scan", state="disabled")
        self.output_text.delete("0.0", "end")
        
        scan_thread = threading.Thread(target=self.run_scan, args=(target,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def run_scan(self, target):
        """Execute the actual scanning logic"""
        try:
            self.update_status("Initializing scan...")
            self.update_progress(0.1)
            
            # Parse target and ports
            ports = self.parse_ports(self.port_entry.get() or "443,8443")
            targets = self.parse_targets(target)
            
            self.log_output(f"Starting scan of {len(targets)} targets on {len(ports)} ports")
            
            total_scans = len(targets) * len(ports)
            completed_scans = 0
            
            for host in targets:
                for port in ports:
                    self.log_output(f"Scanning {host}:{port}...")
                    result = self.scan_host_port(host, port)
                    if result:
                        self.scan_results.append(result)
                        
                    completed_scans += 1
                    progress = 0.1 + (completed_scans / total_scans) * 0.8
                    self.update_progress(progress)
                    
            self.update_progress(1.0)
            self.update_status(f"Scan completed. Found {len(self.scan_results)} services.")
            self.log_output(f"\nScan completed! Analyzed {completed_scans} endpoints.")
            
            # Update results display
            self.root.after(0, self.update_results_display)
            
        except Exception as e:
            self.log_output(f"Error during scan: {str(e)}")
            self.update_status("Scan failed due to error")
        finally:
            self.scan_in_progress = False
            self.root.after(0, lambda: self.scan_button.configure(text="🚀 Start Scan", state="normal"))
            
    def scan_host_port(self, host, port):
        """Scan a specific host:port combination"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert_chain()[0]
                    cert = x509.load_der_x509_certificate(cert_der.public_bytes(serialization.Encoding.DER))
                    
                    # Analyze certificate for PQC
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
                        "pqc_ready": self.analyze_pqc_readiness(cert),
                        "cipher_suites": self.get_cipher_suites(ssock),
                        "vulnerabilities": []
                    }
                    
                    return result
                    
        except Exception as e:
            self.log_output(f"Failed to scan {host}:{port} - {str(e)}")
            return None
            
    def analyze_pqc_readiness(self, cert):
        """Analyze certificate for PQC readiness"""
        sig_alg = cert.signature_algorithm_oid._name.lower()
        
        # Check for quantum-safe algorithms
        pqc_algorithms = ['dilithium', 'falcon', 'sphincs', 'kyber', 'ntru']
        
        for algo in pqc_algorithms:
            if algo in sig_alg:
                return {"ready": True, "algorithm": algo, "confidence": "high"}
                
        # Check for quantum-vulnerable algorithms
        vulnerable_algs = ['rsa', 'ecdsa', 'dsa']
        for algo in vulnerable_algs:
            if algo in sig_alg:
                return {"ready": False, "algorithm": sig_alg, "confidence": "high", "recommendation": "Upgrade to PQC"}
                
        return {"ready": False, "algorithm": sig_alg, "confidence": "medium", "recommendation": "Manual review needed"}
        
    def get_cipher_suites(self, ssl_socket):
        """Get supported cipher suites"""
        try:
            return ssl_socket.cipher()
        except:
            return None
            
    def parse_targets(self, target_string):
        """Parse target specification into list of hosts"""
        targets = []
        for target in target_string.split(','):
            target = target.strip()
            try:
                # Check if it's a CIDR network
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    targets.extend([str(ip) for ip in network.hosts()])
                else:
                    targets.append(target)
            except:
                targets.append(target)  # Assume it's a hostname
        return targets[:50]  # Limit to 50 targets for demo
        
    def parse_ports(self, port_string):
        """Parse port specification into list of ports"""
        ports = []
        for port_spec in port_string.split(','):
            port_spec = port_spec.strip()
            if '-' in port_spec:
                start, end = map(int, port_spec.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(port_spec))
        return ports[:20]  # Limit to 20 ports for demo
        
    def update_progress(self, value):
        """Update progress bar"""
        self.root.after(0, lambda: self.progress_bar.set(value))
        
    def update_status(self, message):
        """Update status label"""
        self.root.after(0, lambda: self.status_label.configure(text=message))
        
    def log_output(self, message):
        """Add message to output log"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.root.after(0, lambda: self.output_text.insert("end", formatted_message))
        
    def update_results_display(self):
        """Update the results display with scan data"""
        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Add new results
        for result in self.scan_results:
            pqc_status = "✅ Ready" if result["pqc_ready"]["ready"] else "❌ Not Ready"
            algorithm = result["pqc_ready"].get("algorithm", "Unknown")
            
            self.results_tree.insert("", "end", values=(
                result["host"],
                result["port"],
                pqc_status,
                algorithm,
                "Active"
            ))
            
    def export_results(self, format_type):
        """Export scan results in specified format"""
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export. Please run a scan first.")
            return
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == "json":
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                initialname=f"pqscan_results_{timestamp}.json"
            )
            if filename:
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                messagebox.showinfo("Export Complete", f"Results exported to {filename}")
                
        elif format_type == "csv":
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialname=f"pqscan_results_{timestamp}.csv"
            )
            if filename:
                df = pd.json_normalize(self.scan_results)
                df.to_csv(filename, index=False)
                messagebox.showinfo("Export Complete", f"Results exported to {filename}")
                
        elif format_type == "pdf":
            messagebox.showinfo("PDF Export", "PDF export functionality coming soon!")
            
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = PQScanApp()
    app.run()
