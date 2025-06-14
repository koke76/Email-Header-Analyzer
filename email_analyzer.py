
import re

def extract_ip_addresses(header):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, header)

def extract_received_lines(header):
    return [line.strip() for line in header.splitlines() if line.lower().startswith("received:")]

def extract_basic_info(header):
    from_ = re.search(r'From: (.+)', header)
    to = re.search(r'To: (.+)', header)
    subject = re.search(r'Subject: (.+)', header)

    return {
        "From": from_.group(1) if from_ else "N/A",
        "To": to.group(1) if to else "N/A",
        "Subject": subject.group(1) if subject else "N/A"
    }

def check_suspicious_keywords(email_body):
    keywords = ['malware', 'virus', 'trojan', 'ransomware', 'phishing', 'exploit', 'attack']
    found = [word for word in keywords if word in email_body.lower()]
    if found:
        print("\n⚠️ Warning: Suspicious keywords detected in email body:", ", ".join(found))
    else:
        print("\nNo suspicious keywords detected in email body.")

def analyze_email(header, body):
    print("=== Email Basic Info ===")
    basic_info = extract_basic_info(header)
    for k, v in basic_info.items():
        print(f"{k}: {v}")

    print("\n=== Received Headers ===")
    received = extract_received_lines(header)
    for i, line in enumerate(received, start=1):
        print(f"{i}. {line}")

    print("\n=== IP Addresses Found ===")
    ips = extract_ip_addresses(header)
    unique_ips = set(ips)
    if unique_ips:
        for ip in unique_ips:
            print(f"- {ip}")
    else:
        print("No IP addresses found in header.")

    check_suspicious_keywords(body)

if __name__ == "__main__":
    print("Paste the full email header. End input with a blank line:\n")
    header_lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        header_lines.append(line)
    header_text = "\n".join(header_lines)

    print("\nPaste the email body. End input with a blank line:\n")
    body_lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        body_lines.append(line)
    body_text = "\n".join(body_lines)

    print("\nAnalyzing email...\n")
    analyze_email(header_text, body_text)
