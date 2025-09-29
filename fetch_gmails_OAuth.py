from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from base64 import urlsafe_b64decode
import email
import re

# Define Gmail API Scope
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def authenticate_gmail():
    """Authenticate using OAuth and return Gmail API service instance."""
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=0)  # Opens browser for login
    service = build("gmail", "v1", credentials=creds)
    return service

def extract_urls(text):
    """Extract all URLs from the email body using regex."""
    url_pattern = r"https?://[^\s]+"  # Simple regex pattern for URLs
    return re.findall(url_pattern, text)

def fetch_unread_emails():
    """Fetch unread emails, extract subject, sender, body, and URLs."""
    service = authenticate_gmail()
    results = service.users().messages().list(userId="me", labelIds=["UNREAD"]).execute()
    messages = results.get("messages", [])

    if not messages:
        print("✅ No unread emails found.")
        return

    for msg in messages:
        email_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        payload = email_data["payload"]
        headers = payload["headers"]
        subject = sender = ""

        for header in headers:
            if header["name"] == "Subject":
                subject = header["value"]
            if header["name"] == "From":
                sender = header["value"]

        # Extract email body
        body = "No body found"
        if "parts" in payload:
            for part in payload["parts"]:
                if part["mimeType"] == "text/plain":
                    body = urlsafe_b64decode(part["body"]["data"]).decode("utf-8")

        # Extract URLs
        urls = extract_urls(body)

        print("=" * 50)
        print(f"📩 **Email from:** {sender}")
        print(f"📌 **Subject:** {subject}")
        print(f"📜 **Body:**\n{body[:500]}...")  # Print first 500 characters
        print(f"🔗 **Extracted URLs:** {urls if urls else 'No URLs found'}")
        print("=" * 50 + "\n")

# Run function to fetch emails and extract URLs
fetch_unread_emails()
