import json
import subprocess

def test_scanner():
    test_data = {
        "processes": [
            {
                "pid": 1234,
                "name": "malware.exe",
                "executable_path": "C:\\Windows\\Temp\\malware.exe",
                "hash": "a94b244f7ee97e701fa78317dfaaf2d55cb85b99c1ca921a651202aa4ac2b3cb",
                "client_id": "TEST_CLIENT"
            }
        ]
    }
    
    input_str = json.dumps(test_data)
    
    process = subprocess.Popen(
        ['python', 'ai_scanner.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    stdout, stderr = process.communicate(input=input_str)
    
    print("STDOUT:")
    print(stdout)
    print("STDERR:")
    print(stderr)

if __name__ == "__main__":
    test_scanner()
