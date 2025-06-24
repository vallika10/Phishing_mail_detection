import re
from collections import defaultdict
from urllib.parse import urlparse

class PhishingDetector:
    def __init__(self):
        self.risk_score = 0
        self.findings = defaultdict(list)
        
        self.legitimate_domains = {
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'aol.com', 'icloud.com', 'protonmail.com'
        }
        
    def check_sender_domain(self, sender_email):
        try:
            domain = sender_email.split('@')[1].lower()
            if domain not in self.legitimate_domains:
                self.risk_score += 2
                self.findings['suspicious_sender'].append(f'Unknown sender domain: {domain}')
        except:
            self.risk_score += 1
            self.findings['suspicious_sender'].append('Invalid sender email format')
    
    def check_urgency_keywords(self, content):
        urgency_patterns = [
            r'\b(urgent|immediate|critical|important)\b',
            r'\b(account.*(?:suspend|terminat|block))\b',
            r'\b(security.*(?:breach|compromised|risk))\b',
            r'\b(limited time|act now|expires?)\b'
        ]
        
        for pattern in urgency_patterns:
            matches = re.finditer(pattern, content.lower())
            for match in matches:
                self.risk_score += 1
                self.findings['urgency'].append(f'Urgent language: {match.group()}')
    
    def check_sensitive_info_requests(self, content):
        sensitive_patterns = [
            r'\b(?:verify|confirm|validate).*(?:account|identity)\b',
            r'\b(?:user.*?(?:name|id)|password|login)\b',
            r'\b(?:credit.*?card|cvv|ssn|social.*?security)\b',
            r'\b(?:bank.*?account|routing.*?number)\b'
        ]
        
        for pattern in sensitive_patterns:
            matches = re.finditer(pattern, content.lower())
            for match in matches:
                self.risk_score += 2
                self.findings['sensitive_info'].append(f'Sensitive info request: {match.group()}')
    
    def check_links(self, content):
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()
                
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                    self.risk_score += 3
                    self.findings['suspicious_links'].append(f'IP address in URL: {url}')
                
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    self.risk_score += 2
                    self.findings['suspicious_links'].append(f'Suspicious TLD: {domain}')
                
                if 'redirect' in url.lower() or 'url=' in url.lower():
                    self.risk_score += 2
                    self.findings['suspicious_links'].append(f'Possible redirect: {url}')
                    
            except:
                self.risk_score += 1
                self.findings['suspicious_links'].append(f'Invalid URL format: {url}')
    
    def analyze_email(self, sender_email, subject, content):
        self.risk_score = 0
        self.findings.clear()
        
        self.check_sender_domain(sender_email)
        full_content = f"{subject}\n{content}"
        
        self.check_urgency_keywords(full_content)
        self.check_sensitive_info_requests(full_content)
        self.check_links(full_content)
        
        risk_level = 'Low' if self.risk_score < 3 else 'Medium' if self.risk_score < 6 else 'High'
        
        return {
            'risk_level': risk_level,
            'risk_score': self.risk_score,
            'findings': dict(self.findings)
        }

def print_analysis_results(result):
    print("\n=== Phishing Email Analysis Results ===")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Risk Score: {result['risk_score']}\n")
    
    if result['findings']:
        print("Suspicious Elements Found:")
        for category, issues in result['findings'].items():
            print(f"\n{category.replace('_', ' ').title()}:")
            for issue in issues:
                print(f"- {issue}")
    else:
        print("No suspicious elements were found in this email.")

def main():
    detector = PhishingDetector()
    
    print("=== Phishing Email Detector ===")
    print("Please enter the email details below:")
    
    sender = input("\nEnter sender's email address: ")
    subject = input("Enter email subject: ")
    print("\nEnter email content (press Enter twice to finish):")
    
    # Collect multi-line content
    content_lines = []
    while True:
        line = input()
        if line == "":
            break
        content_lines.append(line)
    content = "\n".join(content_lines)
    
    # Analyze the email
    result = detector.analyze_email(sender, subject, content)
    
    # Print the results
    print_analysis_results(result)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")