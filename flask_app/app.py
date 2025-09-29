import os
import subprocess
import json
import pandas as pd
from flask import Flask, render_template, request, jsonify
import email
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import torch
import sys
app = Flask(__name__)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FETCH_SCRIPT_PATH = os.path.join(ROOT_DIR, "fetch_gmails_test.py")
PYTHON_EXECUTABLE = r"C:\\Users\\Joel K Jose\\AppData\\Local\\Programs\\VS CODE\\Mini Project\\env\\Scripts\\python.exe"


sys.path.append(ROOT_DIR)

# Import necessary functions from fetch_gmails_test.py
from fetch_gmails_test import (
    check_url_google_safe_browsing,
    get_virustotal_results,
    check_url_urlhaus,
    check_ip_abuseipdb,
    check_spf,
    check_dkim,
    check_dmarc,
    extract_domain
)

def extract_email_components(raw_email):
    """
    Extract components from a raw email including headers, URLs, and text content.
    
    Args:
        raw_email (str): Raw email content
        
    Returns:
        dict: Dictionary containing extracted components
    """
    try:
        # Parse the raw email
        msg = email.message_from_string(raw_email)
        
        # Extract headers
        headers = {}
        for key in msg.keys():
            headers[key] = msg[key]
        
        # Initialize text content
        text_content = ""
        html_content = ""
        
        # Extract body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        if content_type == "text/plain":
                            text_content += payload.decode(errors='replace')
                        elif content_type == "text/html":
                            html_content += payload.decode(errors='replace')
                    except Exception as e:
                        # If decoding fails, try to handle as string
                        try:
                            if isinstance(payload, str):
                                if content_type == "text/plain":
                                    text_content += payload
                                elif content_type == "text/html":
                                    html_content += payload
                        except:
                            pass
        else:
            # If not multipart, just extract the content
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    if msg.get_content_type() == "text/plain":
                        text_content += payload.decode(errors='replace')
                    elif msg.get_content_type() == "text/html":
                        html_content += payload.decode(errors='replace')
                except:
                    # Handle as string if possible
                    if isinstance(payload, str):
                        if msg.get_content_type() == "text/plain":
                            text_content += payload
                        elif msg.get_content_type() == "text/html":
                            html_content += payload
        
        # Extract URLs from HTML content
        urls = []
        if html_content:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                for link in soup.find_all('a', href=True):
                    if link['href'].startswith(('http://', 'https://')):
                        urls.append(link['href'])
            except Exception as e:
                print(f"Error parsing HTML: {e}")
        
        # Extract URLs from plain text using regex
        if text_content:
            # Regular expression for URL extraction
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            text_urls = re.findall(url_pattern, text_content)
            urls.extend(text_urls)
        
        # Remove duplicates and normalize URLs
        normalized_urls = []
        seen_urls = set()
        for url in urls:
            # Basic URL normalization
            try:
                parsed = urlparse(url)
                normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if normalized not in seen_urls:
                    seen_urls.add(normalized)
                    normalized_urls.append(url)
            except Exception as e:
                # If URL parsing fails, add original URL
                if url not in seen_urls:
                    seen_urls.add(url)
                    normalized_urls.append(url)
        
        # Clean duplicate whitespaces and newlines from text content
        if text_content:
            text_content = re.sub(r'\s+', ' ', text_content).strip()
        
        return {
            "headers": headers,
            "urls": normalized_urls,
            "text_content": text_content,
            "html_content": html_content
        }
    except Exception as e:
        return {
            "error": f"Failed to parse email: {str(e)}",
            "headers": {},
            "urls": [],
            "text_content": raw_email,  # Fallback to raw content
            "html_content": ""
        }

def extract_sender_domain(headers):
    """Extract domain from the From or Return-Path header."""
    from_header = headers.get('From', '')
    return_path = headers.get('Return-Path', '')
    
    # Try From header first
    if from_header:
        match = re.search(r'@([^>]+)', from_header)
        if match:
            return match.group(1)
    
    # Try Return-Path next
    if return_path:
        match = re.search(r'@([^>]+)', return_path)
        if match:
            return match.group(1)
    
    return None

def scan_email_urls(urls):
    """
    Scan a list of URLs using integrated security APIs.
    
    Args:
        urls (list): List of URLs to scan
        
    Returns:
        list: List of dictionaries with scan results for each URL
    """
    # Return empty list if no URLs provided
    if not urls:
        return []
        
    results = []
    
    for url in urls:
        try:
            domain = extract_domain(url)
            
            # Check using security APIs
            google_result = check_url_google_safe_browsing(url)
            vt_result = get_virustotal_results(url)
            urlhaus_result = check_url_urlhaus(url)
            abuseipdb_result = check_ip_abuseipdb(url)
            
            results.append({
                "URL": url,
                "Domain": domain,
                "Google Safe Browsing": google_result,
                "VirusTotal": vt_result,
                "URLhaus": urlhaus_result,
                "AbuseIPDB": abuseipdb_result
            })
        except Exception as e:
            results.append({
                "URL": url,
                "Error": str(e)
            })
    
    return results

def run_fetch_script():
    """Runs fetch_gmails_test.py and returns its output file content."""
    try:
        subprocess.run([PYTHON_EXECUTABLE, FETCH_SCRIPT_PATH], check=True)
        results_file = os.path.join(os.path.dirname(os.path.dirname(...)), "security_results.csv")
        if os.path.exists(results_file):
            df = pd.read_csv(results_file)
            return df.to_dict(orient="records")  # Convert DataFrame to list of dicts
        else:
            return {"error": "Results file not found"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to run script: {str(e)}"}

@app.route("/")
def home():
    """Renders the home page."""
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan_url():
    """Triggers fetch_gmails_test.py and returns results."""
    results = run_fetch_script()
    return jsonify(results)

@app.route("/manual_scan", methods=["POST"])
def manual_scan():
    """Allows users to input a URL for scanning."""
    url = request.form.get("url")
    if not url:
        return jsonify({"error": "No URL provided"})
    
    url_pattern = re.compile(r"^(https?:\/\/)?([\w\d-]+\.)+\w{2,}(\/\S*)?$")
    if not url_pattern.match(url):
        return jsonify({"error": "Invalid URL format"}), 400

    # Add http:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    app_output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_results.csv")
    main_output_path = os.path.join(ROOT_DIR, "security_results.csv")
    
    try:
        process = subprocess.run(
            [PYTHON_EXECUTABLE, FETCH_SCRIPT_PATH, "--url", url, "--output", app_output_path, "--append"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=False
        )
        
        if os.path.exists(main_output_path):
            # Add a small delay to ensure file write is complete
            import time
            time.sleep(1)
            
            # Read the entire CSV but filter for the latest scan (our newly added URL)
            df = pd.read_csv(main_output_path)
            
            # Handle NaN values before converting to JSON
            df = df.fillna("N/A")
            
            # Filter for the URL we just scanned
            filtered_df = df[df['URL'] == url]
            
            if not filtered_df.empty:
                # Return only the matching record(s)
                return jsonify(filtered_df.to_dict(orient="records"))
            else:
                # If URL not found, return the last record as a fallback
                return jsonify(df.tail(1).to_dict(orient="records"))
        else:
            return jsonify({
                "error": "Results file not found", 
                "stdout": process.stdout,
                "stderr": process.stderr
            })
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"})

# Load model and tokenizer once
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
model_path = r"C:\Users\Joel K Jose\AppData\Local\Programs\VS CODE\Mini Project\best_distilbert_spam_model\best_distilbert_spam_model"
model = DistilBertForSequenceClassification.from_pretrained(model_path)
tokenizer = DistilBertTokenizer.from_pretrained(model_path)
model.eval()

@app.route('/check_spam', methods=['POST'])
def check_spam():
    data = request.json
    if not data or 'email' not in data:
        return jsonify({"error": "Missing 'email' in request"}), 400

    text = data['email']  # Changed from 'text' to 'email' to match frontend
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        pred_class = torch.argmax(probs).item()
        confidence = probs[0][pred_class].item()

    # Return in format that matches frontend expectations
    return jsonify({
        "prediction": pred_class,  # Changed from "label" to "prediction"
        "confidence": confidence
    })


def evaluate_final_verdict(ai_result, threat_flags):
    """
    Evaluate the final verdict based on AI classification, security scan results,
    and email authentication protocols.
    """
    # Determine threat level from security scan results
    threat_keywords = ['malicious', 'phishing', 'suspicious', 'fail', 'bad']
    threat_level = "Safe"
    
    # Check for malicious indicators in security results
    for k, v in threat_flags.items():
        if any(t in str(v).lower() for t in threat_keywords):
            threat_level = "Malicious"
            break
        elif 'none' in str(v).lower() or 'neutral' in str(v).lower():
            threat_level = "Suspicious"
    
    # Check authentication failures (SPF, DKIM, DMARC)
    auth_failures = 0
    for k in ["SPF", "DKIM", "DMARC"]:
        if k in threat_flags and "❌" in str(threat_flags[k]):
            auth_failures += 1
    
    # Upgrade threat level if authentication failures
    if auth_failures > 0 and threat_level == "Safe":
        threat_level = "Suspicious"
    if auth_failures > 1:
        threat_level = "Malicious"
    
    # Final verdict logic
    if ai_result == "Spam" and threat_level == "Malicious":
        verdict = "Spam email with harmful content. Avoid clicking links or downloading attachments."
    elif ai_result == "Spam" and threat_level == "Safe":
        verdict = "Unwanted promotional spam. Not harmful, but not useful."
    elif ai_result == "Ham" and threat_level == "Malicious":
        verdict = "Legitimate-looking email but contains harmful elements. Be cautious!"
    elif ai_result == "Ham" and threat_level == "Suspicious":
        verdict = "Appears safe but has suspicious traits. Review carefully."
    else:
        verdict = "Legitimate and safe email."
    
    # Add authentication failures to verdict if any
    if auth_failures > 0:
        verdict += f" Note: Email failed {auth_failures} authentication check(s)."
        
    return {
        "ai_result": ai_result,
        "threat_level": threat_level,
        "auth_failures": auth_failures,
        "final_verdict": verdict
    }

@app.route('/analyze_email', methods=['POST'])
def analyze_email():
    data = request.json
    if not data or 'email' not in data:
        return jsonify({"error": "Missing 'email' in request"}), 400

    raw_email = data['email']
    
    # Extract components from raw email
    email_components = extract_email_components(raw_email)
    
    # Check if extraction failed
    if 'error' in email_components and not email_components.get('text_content'):
        return jsonify({"error": email_components['error']}), 400
    
    # Extract sender domain and check authentication protocols
    sender_domain = extract_sender_domain(email_components.get('headers', {}))
    auth_results = {}
    
    if sender_domain:
        auth_results = {
            "domain": sender_domain,
            "SPF": check_spf(sender_domain),
            "DKIM": check_dkim(sender_domain),
            "DMARC": check_dmarc(sender_domain)
        }
    
    # Analyze URLs
    url_results = []
    if email_components.get('urls'):
        url_results = scan_email_urls(email_components['urls'])
    
    # Analyze text content with AI model
    text_classification = {}
    if email_components.get('text_content'):
        try:
            inputs = tokenizer(email_components['text_content'], return_tensors="pt", truncation=True, padding=True)
            
            with torch.no_grad():
                outputs = model(**inputs)
                probs = torch.softmax(outputs.logits, dim=1)
                pred_class = torch.argmax(probs).item()
                confidence = probs[0][pred_class].item()
            
            text_classification = {
                "prediction": pred_class,
                "confidence": confidence
            }
        except Exception as e:
            text_classification = {
                "error": f"Failed to analyze text: {str(e)}",
                "prediction": 0,
                "confidence": 0
            }
    
    # Extract key headers for analysis
    headers_analysis = {}
    headers = email_components.get('headers', {})
    important_headers = ['From', 'To', 'Subject', 'Return-Path', 'Reply-To', 'X-Mailer', 'X-Spam-Status']
    
    for header in important_headers:
        if header in headers:
            headers_analysis[header] = headers[header]
    
    # Calculate suspicious URL count
    suspicious_urls = 0
    for url in url_results:
        if ("MALICIOUS" in url.get("Google Safe Browsing", "") or 
            "MALICIOUS" in url.get("VirusTotal", "") or
            "MALICIOUS" in url.get("URLhaus", "")):
            suspicious_urls += 1

    # Build threat flags from URL analysis and authentication results
    threat_flags = {}
    for url_result in url_results:
        for key, value in url_result.items():
            if key not in ["URL", "Domain"]:  # Skip non-threat fields
                threat_flags[f"{key}_{url_result.get('URL', 'unknown')}"] = value
    
    # Add authentication results to threat flags
    if auth_results:
        for key, value in auth_results.items():
            if key != "domain":  # Skip non-threat fields
                threat_flags[key] = value
    
    # Determine AI classification result
    ai_result = "Spam" if text_classification.get("prediction") == 1 else "Ham"
    
    # Generate final verdict
    verdict = evaluate_final_verdict(ai_result, threat_flags)
    
    # Prepare comprehensive result
    result = {
        "headers_analysis": headers_analysis,
        "url_analysis": url_results,
        "auth_analysis": auth_results,
        "text_analysis": text_classification,
        "summary": {
            "email_has_urls": len(email_components.get('urls', [])) > 0,
            "url_count": len(email_components.get('urls', [])),
            "suspicious_urls": suspicious_urls,
            "text_classification": "SPAM" if text_classification.get("prediction") == 1 else "HAM",
            "text_confidence": text_classification.get("confidence", 0)
        },
        "verdict": verdict
    }
    
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)