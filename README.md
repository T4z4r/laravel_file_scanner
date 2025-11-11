# Laravel File Scanner

A simple Python script to scan Laravel applications for exposed sensitive files and potential data leaks.

## Features

- Scans for common sensitive Laravel file paths (e.g., `.env`, logs, artisan)
- Checks for potential data leaks in accessible files (e.g., APP_KEY, DB_PASSWORD)
- Provides severity levels and recommendations

## Installation

1. Clone or download the repository.
2. Ensure Python 3.6+ is installed.
3. Install dependencies (if any) with `pip install -r requirements.txt`.

## Usage

```bash
python laravel_file_scanner.py <target_url>
```

Replace `<target_url>` with the base URL of the Laravel application to scan (e.g., `https://example.com`).

## Example Output

```
Scanning https://example.com for exposed Laravel files...

🚨 EXPOSED: /.env (Status: 200, Severity: HIGH)
   Potential leaks: APP_KEY=, DB_PASSWORD=
✅ Safe: /storage/logs/laravel.log (404 Not Found)
...

Scan complete. Total findings: 1
Recommendations:
- Block these paths in your web server config (e.g., .htaccess or nginx).
- Use Laravel's built-in protections like `php artisan config:cache`.
- Regularly audit with tools like this or full scanners (e.g., from GitHub).
```

## Disclaimer

This tool is for educational and security auditing purposes only. Use responsibly and with permission on systems you own or have authorization to test.