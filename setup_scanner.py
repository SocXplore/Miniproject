#!/usr/bin/env python3
"""
AI Scanner Configuration Helper
This script helps configure environment variables for the AI scanner.
"""

import os
import sys
from pathlib import Path

def setup_env_file():
    """Create a .env file with scanner configuration"""
    env_path = Path(".env.scanner")
    
    if env_path.exists():
        response = input(".env.scanner already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Skipping .env creation")
            return
    
    print("\n=== AI Scanner Configuration ===\n")
    
    # Get OpenAI API key
    api_key = input("Enter your OpenAI API key (or press Enter to skip AI features): ").strip()
    
    # Get Dashboard URL
    dashboard_url = input("Enter dashboard URL [http://localhost:8080]: ").strip() or "http://localhost:8080"
    
    # Create .env file
    env_content = f"""# AI Scanner Configuration
# Generated configuration for AI Scanner

# OpenAI API Configuration
# Get your key from: https://platform.openai.com/account/api-keys
OPENAI_API_KEY={api_key if api_key else "sk-your-api-key-here"}

# Dashboard Configuration
DASHBOARD_URL={dashboard_url}

# AI Model (gpt-4o-mini is cheaper, gpt-4 is more accurate)
AI_MODEL=gpt-4o-mini

# Scanner Configuration
MALICIOUS_DB=malicious.csv
SCANNER_TIMEOUT=30
"""
    
    with open(env_path, 'w') as f:
        f.write(env_content)
    
    print(f"\n✓ Configuration saved to {env_path}")
    print("\nTo use these settings:")
    print(f"  PowerShell: Get-Content {env_path} | ForEach-Object {{ Invoke-Expression $_ }}")
    print(f"  Bash:       source {env_path}")

def test_scanner():
    """Test if the scanner is properly configured"""
    print("\n=== Testing Scanner Setup ===\n")
    
    # Check Python version
    print(f"✓ Python {sys.version.split()[0]}")
    
    # Check required packages
    required_packages = ['csv', 'json', 'requests', 'typing', 'datetime']
    missing = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package}")
        except ImportError:
            missing.append(package)
            print(f"✗ {package} (missing)")
    
    # Check AI scanner file
    if os.path.exists("ai_scanner.py"):
        print("✓ ai_scanner.py found")
    else:
        print("✗ ai_scanner.py not found")
    
    # Check malicious database
    if os.path.exists("malicious.csv"):
        with open("malicious.csv") as f:
            lines = len(f.readlines())
        print(f"✓ malicious.csv ({lines} lines)")
    else:
        print("✗ malicious.csv not found")
    
    # Check environment variables
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and api_key != "":
        print("✓ OPENAI_API_KEY set")
    else:
        print("⚠ OPENAI_API_KEY not set (AI features will be disabled)")
    
    if missing:
        print(f"\nMissing packages: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
    else:
        print("\n✓ All checks passed!")

def create_requirements_file():
    """Create a requirements.txt file"""
    req_path = Path("requirements.txt")
    
    if req_path.exists():
        print("requirements.txt already exists")
        return
    
    requirements = """# AI Scanner Requirements
requests>=2.28.0
"""
    
    with open(req_path, 'w') as f:
        f.write(requirements)
    
    print("✓ requirements.txt created")

if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════╗
║           ISOLAX AI Scanner Configuration Tool              ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "setup":
            create_requirements_file()
            setup_env_file()
        elif command == "test":
            test_scanner()
        elif command == "requirements":
            create_requirements_file()
        else:
            print(f"Unknown command: {command}")
            print("\nAvailable commands:")
            print("  setup         - Configure environment and API keys")
            print("  test          - Test scanner setup")
            print("  requirements  - Create requirements.txt")
    else:
        # Interactive menu
        while True:
            print("\nWhat would you like to do?")
            print("1. Setup configuration (.env file)")
            print("2. Test scanner setup")
            print("3. Create requirements.txt")
            print("4. Exit")
            
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == "1":
                create_requirements_file()
                setup_env_file()
            elif choice == "2":
                test_scanner()
            elif choice == "3":
                create_requirements_file()
            elif choice == "4":
                print("Goodbye!")
                break
            else:
                print("Invalid choice")
