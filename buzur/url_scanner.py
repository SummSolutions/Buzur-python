# Buzur — Phase 3: Pre-Fetch URL Scanner
# Layered protection: heuristics first, VirusTotal second (optional)
# https://github.com/SummSolutions/buzur-python
#
# Detects:
#   - Suspicious TLDs
#   - Raw IP addresses
#   - Typosquatting and homoglyph domains
#   - Executable file extensions
#   - Unusually long hostnames
#   - Redirect/tracking patterns
#   - Optional VirusTotal reputation check (submit + poll)

import re
import json
import time
import urllib.request
import urllib.parse
from typing import Optional

from buzur.buzur_logger import default_logger, log_threat

# -------------------------------------------------------
# Suspicious TLDs — merged from JS + Python, authoritative list
# -------------------------------------------------------
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.loan', '.gq', '.ml', '.cf', '.tk',
    '.pw', '.cc', '.su', '.rest', '.zip', '.mov',
    '.download', '.review', '.country', '.kim', '.cricket',
    '.science', '.work', '.party', '.ru',
]

# -------------------------------------------------------
# Dangerous file extensions
# -------------------------------------------------------
DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.ps1', '.sh', '.vbs',
    '.jar', '.apk', '.dmg', '.pkg', '.msi', '.dll', '.scr',
]

# -------------------------------------------------------
# Homoglyph domains — common lookalike attack patterns
# -------------------------------------------------------
HOMOGLYPH_PATTERNS = [
    re.compile(r'paypa[l1]\.', re.IGNORECASE),
    re.compile(r'g[o0][o0]g[l1]e\.', re.IGNORECASE),
    re.compile(r'[a4]r?n?azon\.', re.IGNORECASE),
    re.compile(r'micr[o0]s[o0]ft\.', re.IGNORECASE),
    re.compile(r'app[l1]e\.', re.IGNORECASE),
    re.compile(r'faceb[o0][o0]k\.', re.IGNORECASE),
    re.compile(r'tv?v?itter\.', re.IGNORECASE),
    re.compile(r'[l1]inked[l1]n\.', re.IGNORECASE),
]

# -------------------------------------------------------
# Raw IP pattern
# -------------------------------------------------------
RAW_IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# -------------------------------------------------------
# Suspicious hostname and path patterns
# -------------------------------------------------------
SUSPICIOUS_HOSTNAME_PATTERNS = [
    (re.compile(r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.', re.IGNORECASE), "Multiple-hyphen subdomain pattern"),
    (re.compile(r'(free|win|prize|claim|urgent|verify|suspend|alert|secure|login)\.', re.IGNORECASE), "Phishing keyword in hostname"),
    (re.compile(r'[^\x00-\x7F]'), "Non-ASCII characters in hostname"),
]

SUSPICIOUS_PATH_PATTERNS = [
    (re.compile(r'redirect|tracking|click\.php|go\.php', re.IGNORECASE), "Redirect/tracking pattern in path"),
]


# -------------------------------------------------------
# scan_url(url, options)
#
# options: {
#   'virustotal_api_key': str  — optional VirusTotal API key
#   'logger': BuzurLogger      — custom logger (uses default_logger if omitted)
#   'on_threat': str           — 'skip' (default) | 'warn' | 'throw'
# }
#
# Returns:
#   {
#     'verdict': 'clean' | 'suspicious' | 'blocked',
#     'reasons': [...],
#     'url': str,
#     'heuristics': True,
#     'virus_total': None | dict
#   }
# -------------------------------------------------------
def scan_url(url: str, options: dict = None) -> dict:
    options = options or {}
    logger = options.get('logger', default_logger)

    result = {
        'url': url,
        'verdict': 'clean',
        'reasons': [],
        'heuristics': True,
        'virus_total': None,
    }

    if not url:
        result['verdict'] = 'blocked'
        result['reasons'].append('Empty URL')
        log_threat(3, 'url_scanner', result, url, logger)
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': 1, 'reason': 'Buzur blocked URL: empty URL'}
        if on_threat == 'throw':
            raise ValueError('Buzur blocked URL: empty URL')
        return result

    # Parse URL
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or '').lower()
        hostname = re.sub(r'^www\.', '', hostname)
    except Exception:
        result['verdict'] = 'blocked'
        result['reasons'].append('Invalid URL format')
        log_threat(3, 'url_scanner', result, url, logger)
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': 1, 'reason': 'Buzur blocked URL: invalid format'}
        if on_threat == 'throw':
            raise ValueError('Buzur blocked URL: invalid format')
        return result

    if not hostname:
        result['verdict'] = 'blocked'
        result['reasons'].append('Could not parse hostname')
        log_threat(3, 'url_scanner', result, url, logger)
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': 1, 'reason': 'Buzur blocked URL: no hostname'}
        if on_threat == 'throw':
            raise ValueError('Buzur blocked URL: no hostname')
        return result

    # --- Check 1: Raw IP address ---
    if RAW_IP_PATTERN.match(hostname):
        result['reasons'].append('Raw IP address — legitimate services use domain names')

    # --- Check 2: Suspicious hostname patterns ---
    for pattern, reason in SUSPICIOUS_HOSTNAME_PATTERNS:
        if pattern.search(hostname):
            result['reasons'].append(reason)

    # --- Check 3: Suspicious path patterns ---
    for pattern, reason in SUSPICIOUS_PATH_PATTERNS:
        if pattern.search(parsed.path):
            result['reasons'].append(reason)

    # --- Check 4: Suspicious TLD ---
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            result['reasons'].append(f'Suspicious TLD: {tld}')
            break

    # --- Check 5: Homoglyph domain ---
    for pattern in HOMOGLYPH_PATTERNS:
        if pattern.search(hostname):
            result['reasons'].append(f'Homoglyph domain spoof detected: {hostname}')
            break

    # --- Check 6: Dangerous file extension ---
    path = parsed.path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if path.endswith(ext) or f'{ext}?' in path:
            result['reasons'].append(f'Dangerous file extension: {ext}')
            break

    # --- Check 7: Unusually long hostname ---
    if len(hostname) > 50:
        result['reasons'].append(f'Unusually long hostname ({len(hostname)} chars)')

    # --- Check 8: VirusTotal (optional) ---
    api_key = options.get('virustotal_api_key')
    if api_key:
        vt_result = _check_virustotal(url, api_key)
        result['virus_total'] = vt_result
        if vt_result and vt_result.get('verdict') == 'blocked':
            result['reasons'].append(f"VirusTotal: {vt_result.get('malicious', 0)} engine(s) flagged as malicious")
        elif vt_result and vt_result.get('verdict') == 'suspicious':
            result['reasons'].append(f"VirusTotal: {vt_result.get('suspicious', 0)} engine(s) flagged as suspicious")

    # --- Determine verdict ---
    if result['reasons']:
        blocking_signals = ['homoglyph', 'raw ip', 'dangerous', 'virustotal', 'invalid', 'could not']
        if any(
            any(signal in r.lower() for signal in blocking_signals)
            for r in result['reasons']
        ):
            result['verdict'] = 'blocked'
        else:
            result['verdict'] = 'suspicious'

    # --- Log and apply on_threat ---
    if result['verdict'] != 'clean':
        log_threat(3, 'url_scanner', result, url, logger)

    if result['verdict'] == 'blocked':
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': 1, 'reason': f"Buzur blocked URL: {result['reasons'][0]}"}
        if on_threat == 'throw':
            raise ValueError(f"Buzur blocked URL: {result['reasons'][0]}")

    return result


# -------------------------------------------------------
# _check_virustotal(url, api_key)
# Submit URL for analysis then poll up to 3 times for results.
# Mirrors the JS scanUrlVirusTotal submit + poll pattern.
# -------------------------------------------------------
def _check_virustotal(url: str, api_key: str) -> dict:
    try:
        # Step 1: Submit URL for analysis
        data = urllib.parse.urlencode({'url': url}).encode('utf-8')
        submit_req = urllib.request.Request(
            'https://www.virustotal.com/api/v3/urls',
            data=data,
            headers={
                'x-apikey': api_key,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            method='POST',
        )
        with urllib.request.urlopen(submit_req, timeout=10) as resp:
            submit_data = json.loads(resp.read())

        analysis_id = submit_data.get('data', {}).get('id')
        if not analysis_id:
            return {'skipped': True, 'reason': 'No analysis ID returned'}

        # Step 2: Poll for results (up to 3 attempts, 2s apart)
        for _ in range(3):
            time.sleep(2)
            poll_req = urllib.request.Request(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers={'x-apikey': api_key},
            )
            with urllib.request.urlopen(poll_req, timeout=10) as resp:
                analysis_data = json.loads(resp.read())

            attrs = analysis_data.get('data', {}).get('attributes', {})
            if attrs.get('status') != 'completed':
                continue

            stats = attrs.get('stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return {
                'skipped': False,
                'malicious': malicious,
                'suspicious': suspicious,
                'verdict': 'blocked' if malicious > 0 else 'suspicious' if suspicious > 2 else 'clean',
                'engines': stats,
            }

        return {'skipped': True, 'reason': 'VirusTotal analysis timed out'}

    except Exception as e:
        return {'skipped': True, 'reason': f'VirusTotal error: {str(e)}'}