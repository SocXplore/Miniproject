import csv
import json
import sys
import os
import requests
from typing import Dict, List, Set, Tuple
from datetime import datetime

# Configuration
DB_PATH = "malicious.csv"
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8080")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o-mini"

def load_malicious_hashes(filepath: str) -> Set[str]:
    """
    Loads malicious hashes into a set for O(1) lookup.
    Optimized for large CSV files with proper buffering.
    """
    hashes = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace', buffering=65536) as f:
            reader = csv.reader(f, delimiter=',', quotechar='"')
            for row_num, row in enumerate(reader):
                # Skip empty rows
                if not row or len(row) == 0:
                    continue
                
                # Skip header row (row 0)
                if row_num == 0:
                    continue
                
                # Skip comment lines
                if row[0].strip().startswith('#'):
                    continue
                
                # Extract hashes from all available hash columns
                # CSV likely has multiple hash types (sha256, md5, sha1, etc.)
                # Process all non-empty hash values
                for col_idx in range(len(row)):
                    # Clean the hash value: strip spaces and double quotes (sometimes nested)
                    hash_val = row[col_idx].strip().replace('"', '').strip()
                    
                    # Skip empty cells and short values (likely not actual hashes)
                    if hash_val and len(hash_val) >= 32:  # MD5 is 32 chars minimum
                        hashes.add(hash_val.lower())
    except Exception as e:
        print(json.dumps([{"severity": "ERROR", "message": f"Failed to load malicious database: {str(e)}"}]))
        sys.exit(1)
    
    return hashes

def get_all_clients() -> Dict[str, str]:
    """
    Fetches all clients from the dashboard and returns a mapping of client_id -> client_name.
    Client names are derived from hostname or client ID.
    """
    clients = {}
    try:
        # Try to fetch from /api/clients or similar endpoint
        response = requests.get(f"{DASHBOARD_URL}/api/clients", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                for client in data:
                    if isinstance(client, dict):
                        client_id = client.get("id") or client.get("ID")
                        client_name = client.get("name") or client.get("hostname") or client_id
                        if client_id:
                            clients[client_id] = client_name
            elif isinstance(data, dict):
                # If response is a dict with clients as values
                for client_id, client_info in data.items():
                    if isinstance(client_info, dict):
                        client_name = client_info.get("name") or client_info.get("hostname") or client_id
                        clients[client_id] = client_name
                    else:
                        clients[client_id] = str(client_info)
    except Exception as e:
        # Fallback: clients will be empty, we'll handle this gracefully
        pass
    
    return clients

def analyze_process_with_ai(proc: Dict) -> Tuple[str, str]:
    """
    Uses OpenAI API to analyze a process for suspicious behavior.
    Returns (risk_level, analysis_reason)
    """
    if not OPENAI_API_KEY:
        # Log to stderr so it doesn't break JSON output but is visible in server logs
        print("INFO: AI analysis disabled (OPENAI_API_KEY not set)", file=sys.stderr)
        return "UNKNOWN", "AI analysis disabled (no API key)"
    
    try:
        proc_name = proc.get("name", "Unknown")
        proc_path = proc.get("executable_path", "Unknown")
        proc_hash = proc.get("hash", "Unknown")[:16]  # First 16 chars
        
        prompt = f"""Analyze this process for malware/threat indicators:
- Process Name: {proc_name}
- Executable Path: {proc_path}
- Hash (first 16 chars): {proc_hash}

Is this process likely malicious? Respond with ONLY:
MALICIOUS: [brief reason] OR SUSPICIOUS: [reason] OR SAFE: [brief reason]"""
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": OPENAI_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100,
                "temperature": 0.3
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            analysis = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            
            if "MALICIOUS" in analysis:
                reason = analysis.split("MALICIOUS:")[-1].strip() if ":" in analysis else "AI-detected malicious process"
                return "AI_MALICIOUS", reason
            elif "SUSPICIOUS" in analysis:
                reason = analysis.split("SUSPICIOUS:")[-1].strip() if ":" in analysis else "AI-detected suspicious process"
                return "AI_SUSPICIOUS", reason
            else:
                return "SAFE", "AI analysis: appears safe"
        else:
            return "UNKNOWN", "AI analysis failed"
            
    except Exception as e:
        return "UNKNOWN", f"AI analysis error: {str(e)}"

def scan_processes(input_data: Dict, malicious_set: Set[str], clients_map: Dict[str, str]) -> List[Dict]:
    """
    Scans processes and generates alerts for matches using both hash matching and AI analysis.
    Returns JSON array with alerts (empty if safe).
    """
    alerts = []
    processes = input_data.get("processes", [])
    
    if not processes:
        return alerts  # Empty array means scan ran but nothing found
    
    for proc in processes:
        proc_hash = proc.get("hash", "").strip()
        proc_name = proc.get("name", "Unknown")
        client_id = proc.get("client_id", "Unknown")
        
        # Get client name from mapping
        client_name = clients_map.get(client_id, client_id)
        
        # Skip if no hash provided
        if not proc_hash:
            continue
        
        proc_hash_lower = proc_hash.lower()
        
        # Check 1: Hash-based detection (fast)
        if proc_hash_lower in malicious_set:
            alert = {
                "severity": "Critical",
                "type": "Hash Match",
                "message": f"MALWARE DETECTED: {proc_name} is flagged in malware database",
                "file_path": proc.get("executable_path", "Unknown"),
                "pid": str(proc.get("pid", "Unknown")),
                "client_id": client_id,
                "client_name": client_name,
                "hash": proc_hash_lower,
                "timestamp": datetime.now().isoformat(),
                "detection_method": "Hash Database"
            }
            alerts.append(alert)
            continue  # Skip AI analysis if already flagged
        
        # Check 2: AI-based analysis (slower but catches new threats)
        if OPENAI_API_KEY:
            ai_risk, ai_reason = analyze_process_with_ai(proc)
            
            if ai_risk == "AI_MALICIOUS":
                alert = {
                    "severity": "High",
                    "type": "AI Detection",
                    "message": f"AI detected malicious process: {proc_name} - {ai_reason}",
                    "file_path": proc.get("executable_path", "Unknown"),
                    "pid": str(proc.get("pid", "Unknown")),
                    "client_id": client_id,
                    "client_name": client_name,
                    "hash": proc_hash_lower,
                    "timestamp": datetime.now().isoformat(),
                    "detection_method": "AI Analysis",
                    "ai_analysis": ai_reason
                }
                alerts.append(alert)
            
            elif ai_risk == "AI_SUSPICIOUS":
                alert = {
                    "severity": "Medium",
                    "type": "Suspicious Behavior",
                    "message": f"AI flagged suspicious process: {proc_name} - {ai_reason}",
                    "file_path": proc.get("executable_path", "Unknown"),
                    "pid": str(proc.get("pid", "Unknown")),
                    "client_id": client_id,
                    "client_name": client_name,
                    "hash": proc_hash_lower,
                    "timestamp": datetime.now().isoformat(),
                    "detection_method": "AI Analysis",
                    "ai_analysis": ai_reason
                }
                alerts.append(alert)
    
    return alerts

def main():
    # Load DB
    if not os.path.exists(DB_PATH):
        print(json.dumps([{"severity": "ERROR", "message": f"Malicious database not found: {DB_PATH}"}]))
        sys.exit(1)
    
    # Load malicious hashes
    malicious_set = load_malicious_hashes(DB_PATH)
    
    if not malicious_set:
        print(json.dumps([{"severity": "WARNING", "message": "Malicious database loaded but is empty"}]))
        sys.exit(0)
    
    # Get all clients from dashboard
    clients_map = get_all_clients()
    
    # Read stdin with proper buffering
    try:
        input_str = sys.stdin.read()
        if not input_str or not input_str.strip():
            # No input data
            print(json.dumps([]))
            return
        input_data = json.loads(input_str)
    except json.JSONDecodeError as e:
        print(json.dumps([{"severity": "ERROR", "message": f"Invalid JSON input: {str(e)}"}]))
        sys.exit(1)
    except Exception as e:
        print(json.dumps([{"severity": "ERROR", "message": f"Error reading input: {str(e)}"}]))
        sys.exit(1)
    
    # Scan processes with AI and client info
    results = scan_processes(input_data, malicious_set, clients_map)
    
    # Return JSON array (empty if all safe, with alerts if threats found)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
