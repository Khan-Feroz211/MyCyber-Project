#!/usr/bin/env python3
"""
Real-time File System Monitor for DLP System
Monitors specified directories for file changes and triggers DLP scans
"""

import os
import sys
import time
import json
import hashlib
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class DLPEventHandler(FileSystemEventHandler):
    """Handler for file system events with DLP scanning"""
    
    def __init__(self, scanner, watch_directories):
        self.scanner = scanner
        self.watch_directories = watch_directories
        self.file_hashes = {}
        self.threat_log = []
        
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self.process_file(event.src_path, "CREATED")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self.process_file(event.src_path, "MODIFIED")
    
    def process_file(self, filepath, event_type):
        """Process a file with DLP scanner"""
        try:
            # Check if file exists and is readable
            if not os.path.exists(filepath) or not os.path.isfile(filepath):
                return
            
            # Calculate file hash to avoid duplicate processing
            file_hash = self.calculate_file_hash(filepath)
            
            # Skip if file hasn't changed
            if filepath in self.file_hashes and self.file_hashes[filepath] == file_hash:
                return
            
            # Update hash
            self.file_hashes[filepath] = file_hash
            
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🔍 Scanning: {filepath} ({event_type})")
            
            # Scan the single file
            result = self.scanner.scan_file(filepath)
            
            if result.get('threats'):
                self.log_threat(filepath, result['threats'], event_type)
            
        except Exception as e:
            print(f"Error processing {filepath}: {e}")
    
    def calculate_file_hash(self, filepath):
        """Calculate MD5 hash of file content"""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return "error"
    
    def log_threat(self, filepath, threats, event_type):
        """Log detected threats"""
        timestamp = datetime.now().isoformat()
        
        for threat in threats:
            threat_entry = {
                'timestamp': timestamp,
                'file': filepath,
                'event': event_type,
                'threat_type': threat['type'],
                'threat_data': threat.get('data', ''),
                'line': threat.get('line', 0),
                'severity': threat.get('severity', 'medium')
            }
            
            self.threat_log.append(threat_entry)
            
            # Print alert
            print(f"   ⚠️  THREAT DETECTED: {threat['type']}")
            print(f"      File: {os.path.basename(filepath)}")
            print(f"      Path: {filepath}")
            if threat.get('data'):
                print(f"      Data: {threat['data'][:100]}...")
            print(f"      Severity: {threat.get('severity', 'medium').upper()}")
            print()
            
            # Save to log file
            self.save_threat_log()
    
    def save_threat_log(self):
        """Save threat log to file"""
        try:
            log_file = "real_time_threats.json"
            with open(log_file, 'w') as f:
                json.dump(self.threat_log, f, indent=2)
        except Exception as e:
            print(f"Error saving threat log: {e}")

def start_real_time_monitor(directories=None):
    """Start the real-time file system monitor"""
    
    try:
        # Import scanner
        try:
            from dlp_scanner import dlp_scanner as scanner
            print("✅ Loaded dlp_scanner module")
        except ImportError:
            try:
                from scanner_engine import dlp_scanner as scanner
                print("✅ Loaded scanner_engine.dlp_scanner module")
            except ImportError as e:
                print(f"❌ Cannot import scanner module: {e}")
                return False
        
        # Default directories to monitor
        if directories is None:
            directories = [
                "./databases",
                "./uploads",
                "./exports"
            ]
        
        # Create directories if they don't exist
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        print("\n" + "="*60)
        print("🔄 REAL-TIME DLP MONITOR STARTING")
        print("="*60)
        print(f"\n📁 Monitoring directories:")
        for directory in directories:
            print(f"   • {directory}")
        
        print("\n📋 Press Ctrl+C to stop monitoring")
        print("="*60 + "\n")
        
        # Create event handler
        event_handler = DLPEventHandler(scanner, directories)
        
        # Create observer
        observer = Observer()
        
        # Schedule monitoring for each directory
        for directory in directories:
            if os.path.exists(directory):
                observer.schedule(event_handler, directory, recursive=True)
                print(f"✅ Started monitoring: {directory}")
            else:
                print(f"⚠️  Directory not found: {directory}")
        
        # Start observer
        observer.start()
        
        # Initial scan of all monitored directories
        print("\n🔍 Performing initial scan of monitored directories...")
        for directory in directories:
            if os.path.exists(directory):
                print(f"   Scanning: {directory}")
                result = scanner.scan_directory(directory)
                if result['stats']['threats_found'] > 0:
                    print(f"   Found {result['stats']['threats_found']} threats!")
        
        print("\n🎯 Real-time monitoring active. Waiting for file changes...\n")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping real-time monitor...")
            observer.stop()
        
        observer.join()
        return True
        
    except Exception as e:
        print(f"❌ Error starting real-time monitor: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Start monitoring with default directories
    start_real_time_monitor()
