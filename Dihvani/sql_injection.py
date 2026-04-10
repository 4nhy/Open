#!/usr/bin/env python3

import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

class VulnerabilityScanner:
    def __init__(self, base_url):
        if not base_url.startswith("http"):
            base_url = "http://" + base_url

        self.base_url = base_url
        self.headers = {"User-Agent": "Mozilla/5.0"}
        self.results = []

    # -----------------------------
    # Get page content
    # -----------------------------
    def get_page(self, url):
        try:
            return requests.get(url, headers=self.headers, timeout=10).text
        except:
            return ""

    # -----------------------------
    # Extract links
    # -----------------------------
    def get_links(self):
        links = set()
        html = self.get_page(self.base_url)

        found = re.findall(r'href=["\'](.*?)["\']', html)

        for link in found:
            full = urljoin(self.base_url, link)

            if urlparse(full).netloc == urlparse(self.base_url).netloc:
                links.add(full)

        return list(links)

    # -----------------------------
    # Extract forms
    # -----------------------------
    def get_forms(self, url):
        forms = []
        html = self.get_page(url)

        form_blocks = re.findall(r"<form.*?</form>", html, re.DOTALL)

        for form in form_blocks:
            action = re.search(r'action=["\'](.*?)["\']', form)
            method = re.search(r'method=["\'](.*?)["\']', form)

            inputs = re.findall(r'<input.*?name=["\'](.*?)["\']', form)

            forms.append({
                "action": action.group(1) if action else url,
                "method": method.group(1).lower() if method else "get",
                "inputs": inputs
            })

        return forms

    # -----------------------------
    # Extract URLs with parameters
    # -----------------------------
    def get_param_urls(self, urls):
        return [url for url in urls if urlparse(url).query]

    # -----------------------------
    # Inject payload into URL
    # -----------------------------
    def inject_payload(self, url, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        new_params = {k: payload for k in params}
        new_query = urlencode(new_params, doseq=True)

        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    # -----------------------------
    # TRUE/FALSE SQLi detection (GET)
    # -----------------------------
    def test_get_sqli(self, urls):
        print("\n[+] Testing GET parameters (True/False logic)...\n")

        for url in urls:
            try:
                true_payload = "' AND 1=1--"
                false_payload = "' AND 1=2--"

                true_url = self.inject_payload(url, true_payload)
                false_url = self.inject_payload(url, false_payload)

                true_res = self.get_page(true_url)
                false_res = self.get_page(false_url)

                if true_res != false_res:
                    print("[!!!] LIKELY SQL INJECTION")
                    print("URL:", url)
                    print("-" * 50)

                    self.results.append({
                        "type": "GET",
                        "url": url,
                        "payload": "True/False logic",
                        "status": "Likely SQL Injection"
                    })

            except Exception as e:
                print("Error:", e)

    # -----------------------------
    # TRUE/FALSE SQLi detection (FORMS)
    # -----------------------------
    def test_forms(self, urls):
        print("\n[+] Testing Forms (True/False logic)...\n")

        for url in urls:
            forms = self.get_forms(url)

            for form in forms:
                action = urljoin(url, form["action"])
                method = form["method"]
                inputs = form["inputs"]

                try:
                    true_data = {i: "' AND 1=1--" for i in inputs}
                    false_data = {i: "' AND 1=2--" for i in inputs}

                    true_res = requests.request(method, action, data=true_data, headers=self.headers).text
                    false_res = requests.request(method, action, data=false_data, headers=self.headers).text

                    if true_res != false_res:
                        print("[!!!] LIKELY SQL INJECTION (FORM)")
                        print("Form Action:", action)
                        print("-" * 50)

                        self.results.append({
                            "type": "FORM",
                            "url": action,
                            "payload": "True/False logic",
                            "status": "Likely SQL Injection"
                        })

                except Exception as e:
                    print("Form error:", e)

    # -----------------------------
    # Report
    # -----------------------------
    def report(self):
        print("\n[+] Final Report\n")

        if not self.results:
            print("No vulnerabilities detected.")

        for r in self.results:
            print(f"Type: {r['type']}")
            print(f"URL: {r['url']}")
            print(f"Status: {r['status']}")
            print("-" * 40)


# -----------------------------
# MAIN
# -----------------------------
def main():
    target = input("Enter URL: ").strip()

    scanner = VulnerabilityScanner(target)

    print("\n[+] Crawling...\n")
    links = scanner.get_links()

    if target not in links:
        links.append(target)

    print(f"[+] Found {len(links)} pages")

    param_urls = scanner.get_param_urls(links)

    # fallback if crawling fails
    if not param_urls and "?" in target:
        print("[*] Using direct URL for testing.")
        param_urls = [target]

    print(f"[+] Found {len(param_urls)} parameterized URLs")

    scanner.test_get_sqli(param_urls)
    scanner.test_forms(links)

    scanner.report()


if __name__ == "__main__":
    main()