#!/usr/bin/env python3
"""
PQScan Launcher - Easy access to both terminal and GUI versions
"""

import sys
import os
import subprocess

def show_launcher_menu():
    """Display the launcher menu"""
    menu = """
╔══════════════════════════════════════════════════════════════╗
║                    🔐 PQScan Launcher 🔐                     ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Choose your preferred interface:                            ║
║                                                              ║
║  1. 🖥️  GUI Version     - Beautiful graphical interface     ║
║  2. 💻 Terminal Version - Command-line power user tool       ║
║  3. 📚 Show Examples    - Usage examples and demonstrations  ║
║  4. 🔍 Quick Scan       - Fast scan with default settings    ║
║  5. ℹ️  Help            - Show detailed help information     ║
║  6. 🚪 Exit             - Close launcher                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Enter your choice (1-6): """
    
    return input(menu).strip()

def launch_gui():
    """Launch the GUI version"""
    print("🚀 Launching PQScan GUI...")
    try:
        subprocess.run([sys.executable, "main.py"])
    except KeyboardInterrupt:
        print("\n👋 GUI closed by user")
    except Exception as e:
        print(f"❌ Error launching GUI: {e}")

def launch_terminal():
    """Launch terminal version with user input"""
    print("\n💻 PQScan Terminal Mode")
    print("=" * 30)
    
    target = input("🎯 Enter target (IP, domain, or CIDR): ").strip()
    if not target:
        print("❌ No target specified")
        return
        
    ports = input("🔌 Enter ports (default: 443): ").strip() or "443"
    verbose = input("🔍 Verbose output? (y/N): ").strip().lower() == 'y'
    output_file = input("💾 Save to file (optional): ").strip()
    
    # Build command
    cmd = [sys.executable, "pqscan_terminal.py"]
    
    if verbose:
        cmd.append("-v")
    if ports != "443":
        cmd.extend(["-p", ports])
    if output_file:
        cmd.extend(["-o", output_file])
    
    cmd.append(target)
    
    print(f"\n🚀 Running: {' '.join(cmd)}")
    print("=" * 50)
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error running scan: {e}")

def show_examples():
    """Show usage examples"""
    try:
        subprocess.run([sys.executable, "examples.py"])
    except Exception as e:
        print(f"❌ Error showing examples: {e}")

def quick_scan():
    """Perform a quick scan with minimal input"""
    print("\n⚡ Quick Scan Mode")
    print("=" * 20)
    
    target = input("🎯 Enter target: ").strip()
    if not target:
        print("❌ No target specified")
        return
        
    print("🚀 Running quick scan...")
    cmd = [sys.executable, "pqscan_terminal.py", "-v", target]
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error running scan: {e}")

def show_help():
    """Show help information"""
    try:
        subprocess.run([sys.executable, "pqscan_terminal.py", "--help"])
    except Exception as e:
        print(f"❌ Error showing help: {e}")

def main():
    """Main launcher function"""
    print("🔐 Welcome to PQScan!")
    
    while True:
        choice = show_launcher_menu()
        
        if choice == "1":
            launch_gui()
        elif choice == "2":
            launch_terminal()
        elif choice == "3":
            show_examples()
        elif choice == "4":
            quick_scan()
        elif choice == "5":
            show_help()
        elif choice == "6":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1-6.")
        
        if choice in ["1", "2", "3", "4", "5"]:
            input("\n📍 Press Enter to return to menu...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Launcher closed by user")
    except Exception as e:
        print(f"\n❌ Launcher error: {e}")