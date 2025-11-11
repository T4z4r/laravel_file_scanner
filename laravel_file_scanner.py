#!/usr/bin/env python3
import urllib.request
import urllib.error
import re
import sys
from urllib.parse import urljoin

# List of common sensitive paths in Laravel apps
SENSITIVE_PATHS = [
    '/.env',
    '/.env.backup',
    '/.env.bak',
    '/.env~',
    '/backup/.env',
    '/storage/.env',
    '/config/.env',
    '/public/.env',
    '/.env.local',
    '/storage/logs/laravel.log',  # Debug logs might leak info
    '/artisan',  # Should not be web-accessible
]

# Regex patterns for sensitive data in responses
SENSITIVE_PATTERNS = [
    r'APP_KEY=',
    r'DB_PASSWORD=',
    r'AWS_ACCESS_KEY_ID=',
    r'REDIS_PASSWORD=',
]

def scan_url(base_url, path):
    """Send a HEAD request to check if the path is accessible."""
    target_url = urljoin(base_url, path)
    try:
        req = urllib.request.Request(target_url, method='HEAD')
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            if status == 200:
                # If HEAD works, do a GET to check content
                req = urllib.request.Request(target_url)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    content = resp.read().decode('utf-8', errors='ignore')
                    leaks = [pat for pat in SENSITIVE_PATTERNS if re.search(pat, content)]
                    return True, status, leaks
            return False, status, []
    except urllib.error.HTTPError as e:
        return False, e.code, []
    except Exception:
        return False, None, []

def main():
    if len(sys.argv) != 2:
        print("Usage: python laravel_file_scanner.py <target_url>")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    
    print(f"Scanning {base_url} for exposed Laravel files...\n")
    
    findings = []
    for path in SENSITIVE_PATHS:
        accessible, status, leaks = scan_url(base_url, path)
        if accessible or status == 200:
            severity = "HIGH" if leaks else "MEDIUM"
            findings.append({
                'path': path,
                'status': status,
                'leaks': leaks,
                'severity': severity
            })
            print(f"🚨 EXPOSED: {path} (Status: {status}, Severity: {severity})")
            if leaks:
                print(f"   Potential leaks: {', '.join(leaks)}")
        elif status == 404:
            print(f"✅ Safe: {path} (404 Not Found)")
        else:
            print(f"⚠️  Unknown: {path} (Status: {status})")
    
    print(f"\nScan complete. Total findings: {len(findings)}")
    if findings:
        print("Recommendations:")
        print("- Block these paths in your web server config (e.g., .htaccess or nginx).")
        print("- Use Laravel's built-in protections like `php artisan config:cache`.")
        print("- Regularly audit with tools like this or full scanners (e.g., from GitHub).")

if __name__ == "__main__":
    main()