import csv
from collections import Counter

file_path = r'c:\Users\ADMIN\OneDrive\Documents\Desktop\pro\ISOLAX\isola\isola\malicious.csv'

def get_unique_signatures():
    signatures = Counter()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            # Skip initial comment lines
            pos = 0
            line = f.readline()
            while line.startswith('#'):
                pos = f.tell()
                line = f.readline()
            f.seek(pos)
            
            reader = csv.DictReader(f)
            # Normalize column names by stripping quotes and spaces
            reader.fieldnames = [name.strip().replace('"', '') for name in reader.fieldnames]
            
            for row in reader:
                sig = row.get('signature')
                if sig and sig.lower() != 'n/a':
                    signatures[sig] += 1
                    
        return signatures.most_common(50) # Return top 50 for now

    except Exception as e:
        print(f"Error: {e}")
        return []

if __name__ == "__main__":
    top_signatures = get_unique_signatures()
    print("Top 50 Malware Signatures:")
    for sig, count in top_signatures:
        print(f"{sig}: {count}")
