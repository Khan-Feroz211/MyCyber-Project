#!/usr/bin/env python3
"""
Unified DLP System Runner
Starts all components of the DLP system
"""

import os
import sys
import subprocess
import time
import threading
from datetime import datetime

def run_web_app():
    """Run the Flask web application"""
    print("\n" + "="*60)
    print("🌐 STARTING DLP WEB APPLICATION")
    print("="*60)
    
    try:
        # Check if app.py exists
        if not os.path.exists("app.py"):
            print("❌ app.py not found!")
            return False
        
        print("Starting Flask application on http://localhost:5000")
        print("Default login: admin / admin123")
        print("Press Ctrl+C in this terminal to stop the web app")
        print("-"*60)
        
        # Run the Flask app
        subprocess.run([sys.executable, "app.py"])
        
    except KeyboardInterrupt:
        print("\n🛑 Web application stopped")
    except Exception as e:
        print(f"❌ Error running web app: {e}")
        return False
    
    return True

def run_real_time_monitor():
    """Run the real-time monitor in a separate thread"""
    print("\n" + "="*60)
    print("🔄 STARTING REAL-TIME MONITOR")
    print("="*60)
    
    try:
        # Check if real_time_monitor.py exists
        if not os.path.exists("real_time_monitor.py"):
            print("❌ real_time_monitor.py not found!")
            return False
        
        print("Starting real-time file system monitor")
        print("Monitoring: ./databases, ./uploads, ./exports")
        print("-"*60)
        
        # Run the monitor
        subprocess.run([sys.executable, "real_time_monitor.py"])
        
    except KeyboardInterrupt:
        print("\n🛑 Real-time monitor stopped")
    except Exception as e:
        print(f"❌ Error running real-time monitor: {e}")
        return False
    
    return True

def run_scanner_test():
    """Run a quick test of the scanner"""
    print("\n" + "="*60)
    print("🔍 TESTING DLP SCANNER")
    print("="*60)
    
    try:
        # Import scanner from scanner_engine
        from scanner_engine import dlp_scanner
        scanner = dlp_scanner
        print("✅ Loaded scanner from scanner_engine.py")
        
        # Test scan
        test_dir = "databases"
        if os.path.exists(test_dir):
            print(f"\nScanning directory: {test_dir}")
            result = scanner.scan_directory(test_dir)
            
            print(f"\n📊 SCAN RESULTS:")
            print(f"   Scan ID: {result.get('id', 'N/A')}")
            print(f"   Files scanned: {result.get('stats', {}).get('scanned_files', 0)}")
            print(f"   Threats found: {result.get('stats', {}).get('threats_found', 0)}")
            
            if result.get('threats'):
                print(f"\n🔍 Threat breakdown:")
                threat_types = {}
                for threat in result['threats']:
                    t_type = threat['type']
                    threat_types[t_type] = threat_types.get(t_type, 0) + 1
                
                for ttype, count in threat_types.items():
                    print(f"   • {ttype}: {count}")
                
                print(f"\n📝 Sample threats:")
                for i, threat in enumerate(result['threats'][:3]):  # Show first 3
                    print(f"   {i+1}. [{threat['severity'].upper()}] {threat['type']}")
                    print(f"      File: {os.path.basename(threat['file'])}")
                    print(f"      Data: {threat.get('data', '')[:50]}...")
                    print()
                
                if len(result['threats']) > 3:
                    print(f"   ... and {len(result['threats']) - 3} more threats")
            else:
                print("\n✅ No threats found!")
            
            return True
        else:
            print(f"❌ Test directory '{test_dir}' not found!")
            print("Creating a test file...")
            
            # Create test file
            test_content = """Test file with sensitive data:
SSN: 123-45-6789
Credit Card: 4111-1111-1111-1111
Email: test@example.com
Password: password="secret123"
"""
            with open("test_dlp.txt", "w") as f:
                f.write(test_content)
            
            result = scanner.scan_file("test_dlp.txt")
            print(f"Found {len(result.get('threats', []))} threats in test file")
            return True
            
    except ImportError as e:
        print(f"❌ Cannot import scanner module: {e}")
        print("\nTrying alternative import methods...")
        
        # Try alternative import
        try:
            import scanner_engine
            scanner = scanner_engine.dlp_scanner
            print("✅ Imported via alternative method")
            
            # Quick test
            if os.path.exists("databases"):
                result = scanner.scan_directory("databases")
                print(f"Found {result.get('stats', {}).get('threats_found', 0)} threats!")
                return True
        except Exception as e2:
            print(f"❌ Still failed: {e2}")
            return False
    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main function to run the DLP system"""
    print("\n" + "="*60)
    print("🚀 DATA LOSS PREVENTION (DLP) SYSTEM")
    print("="*60)
    
    print("\n📁 Your test databases are ready in: databases/")
    print("   Contains: SSNs, Credit Cards, Passwords, etc.")
    
    print("\nAvailable options:")
    print("1. 🔍 Quick Scanner Test (check databases)")
    print("2. 🌐 Web Application (app.py)")
    print("3. 🔄 Real-time Monitor")
    print("4. 🏃 Run All Components")
    print("5. 🚪 Exit")
    
    while True:
        try:
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                if run_scanner_test():
                    input("\nPress Enter to return to menu...")
                continue
            elif choice == "2":
                run_web_app()
                break
            elif choice == "3":
                run_real_time_monitor()
                break
            elif choice == "4":
                print("\n🚀 Starting all DLP components...")
                print("\n📝 Starting web application...")
                print("📝 Open another terminal to run: python3 real_time_monitor.py")
                run_web_app()
                break
            elif choice == "5":
                print("\n👋 Exiting DLP System")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please enter 1-5")
                
        except KeyboardInterrupt:
            print("\n\n👋 Exiting DLP System")
            sys.exit(0)
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
