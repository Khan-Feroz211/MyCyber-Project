#!/usr/bin/env python3
"""
DLP Scanner Engine
Main module for scanning files and detecting sensitive data leaks
"""

import os
import re
import json
import hashlib
import pandas as pd
from datetime import datetime
from pathlib import Path

class DLPScanner:
    """Main DLP scanner class"""
    
    def __init__(self):
        self.patterns = {
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'CREDIT_CARD': r'\b(?:\d[ -]*?){13,16}\b',
            'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'PHONE': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
            'API_KEY': r'\b(?:sk|pk)_[a-zA-Z0-9]{24,}\b',
            'PASSWORD': r'password\s*[:=]\s*[\'"][^\'"]+[\'"]',
            'DATABASE_URL': r'(?:postgres|mysql|mongodb)://[^\s]+',
            'SECRET': r'(?:secret|api[_-]?key|token)\s*[:=]\s*[\'"][^\'"]+[\'"]',
            'BANK_ACCOUNT': r'\b\d{8,17}\b',
            'IP_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }
        
        self.threat_severity = {
            'SSN': 'high',
            'CREDIT_CARD': 'high',
            'API_KEY': 'critical',
            'PASSWORD': 'critical',
            'DATABASE_URL': 'high',
            'SECRET': 'high',
            'BANK_ACCOUNT': 'medium',
            'EMAIL': 'low',
            'PHONE': 'low',
            'IP_ADDRESS': 'medium'
        }
        
        self.scan_id_counter = 1
        self.integrity_data = {}
        
    def load_integrity_data(self):
        """Load integrity data for scanning"""
        # This can be expanded to load from a file or database
        self.integrity_data = {
            'allowed_files': [],
            'baseline_hashes': {},
            'sensitive_patterns': self.patterns
        }
        return True
    
    def scan_file(self, filepath):
        """Scan a single file for sensitive data"""
        threats = []
        
        if not os.path.exists(filepath):
            return {'file': filepath, 'threats': threats, 'error': 'File not found'}
        
        try:
            file_ext = os.path.splitext(filepath)[1].lower()
            
            # Read file based on type
            if file_ext in ['.txt', '.log', '.sql', '.env', '.config', '.conf']:
                content = self.read_text_file(filepath)
                threats = self.scan_text_content(content, filepath)
                
            elif file_ext in ['.csv']:
                threats = self.scan_csv_file(filepath)
                
            elif file_ext in ['.xlsx', '.xls']:
                threats = self.scan_excel_file(filepath)
                
            elif file_ext in ['.json']:
                threats = self.scan_json_file(filepath)
                
            else:
                # Try to read as text file
                try:
                    content = self.read_text_file(filepath)
                    threats = self.scan_text_content(content, filepath)
                except:
                    return {'file': filepath, 'threats': threats, 'error': 'Unsupported file type'}
            
            return {
                'file': filepath,
                'threats': threats,
                'threat_count': len(threats),
                'scan_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'file': filepath, 'threats': threats, 'error': str(e)}
    
    def scan_directory(self, directory_path):
        """Scan all files in a directory recursively"""
        scan_id = f"scan_{self.scan_id_counter:06d}_{int(datetime.now().timestamp())}"
        self.scan_id_counter += 1
        
        start_time = datetime.now()
        all_threats = []
        scanned_files = []
        file_count = 0
        threat_count = 0
        
        if not os.path.exists(directory_path):
            return {
                'id': scan_id,
                'directory': directory_path,
                'threats': [],
                'stats': {
                    'scanned_files': 0,
                    'threats_found': 0,
                    'total_files': 0
                },
                'error': 'Directory not found'
            }
        
        try:
            # Walk through directory
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_count += 1
                    
                    # Skip very large files (>10MB)
                    if os.path.getsize(file_path) > 10 * 1024 * 1024:
                        continue
                    
                    print(f"  Scanning: {file}")
                    result = self.scan_file(file_path)
                    scanned_files.append(file_path)
                    
                    if 'threats' in result and result['threats']:
                        all_threats.extend(result['threats'])
                        threat_count += len(result['threats'])
            
            scan_time = (datetime.now() - start_time).total_seconds()
            
            return {
                'id': scan_id,
                'directory': directory_path,
                'timestamp': start_time.isoformat(),
                'threats': all_threats,
                'scanned_files': scanned_files,
                'stats': {
                    'scanned_files': len(scanned_files),
                    'threats_found': threat_count,
                    'total_files': file_count,
                    'scan_time_seconds': scan_time
                }
            }
            
        except Exception as e:
            return {
                'id': scan_id,
                'directory': directory_path,
                'threats': all_threats,
                'scanned_files': scanned_files,
                'stats': {
                    'scanned_files': len(scanned_files),
                    'threats_found': threat_count,
                    'total_files': file_count
                },
                'error': str(e)
            }
    
    def read_text_file(self, filepath):
        """Read text file with proper encoding"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            with open(filepath, 'r', encoding='latin-1') as f:
                return f.read()
    
    def scan_text_content(self, content, filepath):
        """Scan text content for sensitive patterns"""
        threats = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern in self.patterns.items():
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    threat = {
                        'type': pattern_name,
                        'file': filepath,
                        'line': line_num,
                        'data': match.group(),
                        'severity': self.threat_severity.get(pattern_name, 'medium'),
                        'context': line.strip()[:200]
                    }
                    threats.append(threat)
        
        return threats
    
    def scan_csv_file(self, filepath):
        """Scan CSV file for sensitive data"""
        threats = []
        
        try:
            # Read CSV with pandas
            df = pd.read_csv(filepath)
            
            # Convert dataframe to string for pattern matching
            csv_text = df.to_string(index=False)
            text_threats = self.scan_text_content(csv_text, filepath)
            threats.extend(text_threats)
            
            # Also check column names for sensitive info
            for col in df.columns:
                for pattern_name, pattern in self.patterns.items():
                    if re.search(pattern, str(col), re.IGNORECASE):
                        threat = {
                            'type': f'COLUMN_{pattern_name}',
                            'file': filepath,
                            'line': 1,
                            'data': str(col),
                            'severity': self.threat_severity.get(pattern_name, 'medium'),
                            'context': f'Column name contains sensitive pattern'
                        }
                        threats.append(threat)
                        
        except Exception as e:
            # If pandas fails, try as text file
            try:
                content = self.read_text_file(filepath)
                threats = self.scan_text_content(content, filepath)
            except:
                pass
        
        return threats
    
    def scan_excel_file(self, filepath):
        """Scan Excel file for sensitive data"""
        threats = []
        
        try:
            # Read Excel with pandas
            xls = pd.ExcelFile(filepath)
            
            for sheet_name in xls.sheet_names:
                df = pd.read_excel(xls, sheet_name=sheet_name)
                
                # Convert sheet to string for pattern matching
                sheet_text = df.to_string(index=False)
                text_threats = self.scan_text_content(sheet_text, filepath)
                
                # Add sheet name to threats
                for threat in text_threats:
                    threat['sheet'] = sheet_name
                    threats.append(threat)
                
                # Check column names
                for col in df.columns:
                    for pattern_name, pattern in self.patterns.items():
                        if re.search(pattern, str(col), re.IGNORECASE):
                            threat = {
                                'type': f'EXCEL_COLUMN_{pattern_name}',
                                'file': filepath,
                                'sheet': sheet_name,
                                'line': 1,
                                'data': str(col),
                                'severity': self.threat_severity.get(pattern_name, 'medium'),
                                'context': f'Excel column name contains sensitive pattern'
                            }
                            threats.append(threat)
                            
        except Exception as e:
            # Fallback to text scanning
            print(f"  Warning: Could not parse Excel file {filepath}: {e}")
        
        return threats
    
    def scan_json_file(self, filepath):
        """Scan JSON file for sensitive data"""
        threats = []
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Convert JSON to string for pattern matching
            json_text = json.dumps(data)
            threats = self.scan_text_content(json_text, filepath)
            
        except Exception as e:
            # If JSON parsing fails, try as text file
            try:
                content = self.read_text_file(filepath)
                threats = self.scan_text_content(content, filepath)
            except:
                pass
        
        return threats
    
    def get_scan_summary(self, scan_result):
        """Get a summary of scan results"""
        if 'error' in scan_result:
            return f"Scan failed: {scan_result['error']}"
        
        stats = scan_result.get('stats', {})
        return f"Scanned {stats.get('scanned_files', 0)} files, found {stats.get('threats_found', 0)} threats"
    
    def export_results(self, scan_result, format='json'):
        """Export scan results to different formats"""
        if format.lower() == 'json':
            return json.dumps(scan_result, indent=2)
        elif format.lower() == 'csv':
            # Create CSV from threats
            import io
            import csv
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Type', 'File', 'Severity', 'Data', 'Line', 'Context'])
            
            # Write threats
            for threat in scan_result.get('threats', []):
                writer.writerow([
                    threat.get('type', ''),
                    threat.get('file', ''),
                    threat.get('severity', ''),
                    threat.get('data', ''),
                    threat.get('line', ''),
                    threat.get('context', '')[:100]
                ])
            
            return output.getvalue()
        else:
            return str(scan_result)

# Create global scanner instance
dlp_scanner = DLPScanner()

if __name__ == "__main__":
    # Test the scanner
    scanner = DLPScanner()
    
    print("🔍 DLP Scanner Test")
    print("=" * 50)
    
    # Test with databases directory
    if os.path.exists("databases"):
        print("Scanning 'databases' directory...")
        result = scanner.scan_directory("databases")
        
        print(f"\n📊 Scan Results:")
        print(f"  ID: {result.get('id', 'N/A')}")
        print(f"  Directory: {result.get('directory', 'N/A')}")
        print(f"  Files scanned: {result.get('stats', {}).get('scanned_files', 0)}")
        print(f"  Threats found: {result.get('stats', {}).get('threats_found', 0)}")
        
        if result.get('threats'):
            print(f"\n🔍 Threats found:")
            for i, threat in enumerate(result['threats'][:5]):  # Show first 5
                print(f"  {i+1}. [{threat['severity'].upper()}] {threat['type']}")
                print(f"     File: {os.path.basename(threat['file'])}")
                print(f"     Data: {threat['data'][:50]}...")
                print()
            
            if len(result['threats']) > 5:
                print(f"  ... and {len(result['threats']) - 5} more threats")
        else:
            print("\n✅ No threats found!")
    else:
        print("❌ 'databases' directory not found!")
        print("\nCreating a test file to scan...")
        
        # Create a test file with sensitive data
        test_content = """Test file with sensitive data:
SSN: 123-45-6789
Credit Card: 4111-1111-1111-1111
Email: test@example.com
Password: password="secret123"
API Key: sk_test_FAKESTRIPEKEY1234567890abc
"""
        
        with open("test_sensitive.txt", "w") as f:
            f.write(test_content)
        
        print("Created test_sensitive.txt")
        result = scanner.scan_file("test_sensitive.txt")
        print(f"Found {len(result.get('threats', []))} threats in test file")
