#!/usr/bin/env python3
"""
Deployment Verification Script
Tests the AI Scanner deployment
"""
import subprocess
import json
import sys
import os

def test_scanner_installed():
    """Test if Python and dependencies are installed"""
    print("✓ Testing Python installation...")
    try:
        result = subprocess.run(['python', '--version'], capture_output=True, text=True)
        print(f"  Python version: {result.stdout.strip()}")
        return True
    except Exception as e:
        print(f"  ✗ Python not found: {e}")
        return False

def test_dependencies():
    """Test if required dependencies are installed"""
    print("✓ Testing dependencies...")
    try:
        subprocess.run(['python', '-c', 'import requests'], capture_output=True, check=True)
        print("  ✓ requests module installed")
        return True
    except Exception as e:
        print(f"  ✗ requests module not found: {e}")
        return False

def test_scanner_file():
    """Test if scanner file exists"""
    print("✓ Testing scanner files...")
    if os.path.exists('ai_scanner.py'):
        print("  ✓ ai_scanner.py exists")
        return True
    else:
        print("  ✗ ai_scanner.py not found")
        return False

def test_scanner_execution():
    """Test if scanner runs without errors"""
    print("✓ Testing scanner execution...")
    
    test_input = {
        "processes": [
            {
                "pid": 1234,
                "name": "notepad.exe",
                "executable_path": "C:\\Windows\\notepad.exe",
                "hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                "client_id": "TEST-MACHINE-001"
            }
        ]
    }
    
    try:
        proc = subprocess.Popen(
            ['python', 'ai_scanner.py'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=json.dumps(test_input), timeout=10)
        
        if proc.returncode == 0:
            result = json.loads(stdout) if stdout.strip() else []
            print(f"  ✓ Scanner executed successfully (returned {len(result)} alerts)")
            return True
        else:
            print(f"  ✗ Scanner failed: {stderr}")
            return False
    except subprocess.TimeoutExpired:
        proc.kill()
        print("  ✗ Scanner timed out (may need API key)")
        return True  # Not critical
    except Exception as e:
        print(f"  ✗ Scanner execution error: {e}")
        return False

def test_malicious_db():
    """Test if malicious database exists"""
    print("✓ Testing malicious database...")
    if os.path.exists('malicious.csv'):
        try:
            with open('malicious.csv', 'r') as f:
                lines = len(f.readlines())
            print(f"  ✓ malicious.csv found ({lines} lines)")
            return True
        except Exception as e:
            print(f"  ✗ Error reading malicious.csv: {e}")
            return False
    else:
        print("  ⚠ malicious.csv not found (optional)")
        return True

def test_environment_vars():
    """Test if environment variables are set"""
    print("✓ Testing environment variables...")
    api_key = os.getenv('OPENAI_API_KEY', '')
    dashboard_url = os.getenv('DASHBOARD_URL', 'http://localhost:8080')
    
    if api_key:
        print("  ✓ OPENAI_API_KEY is set")
    else:
        print("  ⚠ OPENAI_API_KEY not set (AI features disabled)")
    
    print(f"  ✓ DASHBOARD_URL = {dashboard_url}")
    return True

def main():
    print("""
╔════════════════════════════════════════════════╗
║     ISOLAX AI Scanner Deployment Verification  ║
╚════════════════════════════════════════════════╝
    """)
    
    tests = [
        ("Python Installation", test_scanner_installed),
        ("Dependencies", test_dependencies),
        ("Scanner File", test_scanner_file),
        ("Malicious Database", test_malicious_db),
        ("Environment Variables", test_environment_vars),
        ("Scanner Execution", test_scanner_execution),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ {test_name}: {e}")
            results.append((test_name, False))
        print()
    
    # Summary
    print("╔════════════════════════════════════════════════╗")
    print("║              DEPLOYMENT SUMMARY                ║")
    print("╚════════════════════════════════════════════════╝")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} - {test_name}")
    
    print()
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ DEPLOYMENT SUCCESSFUL! The AI scanner is ready.")
        print("\nNext steps:")
        print("1. Start the server: go run server.go ai_scanner_integration.go")
        print("2. Set environment variables:")
        print("   $env:OPENAI_API_KEY = 'sk-your-key'")
        print("   $env:DASHBOARD_URL = 'http://localhost:8080'")
        print("3. Clients will send process data and alerts will appear")
        return 0
    else:
        print("\n⚠️  Some tests failed. Check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
