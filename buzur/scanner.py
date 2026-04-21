# Buzur — AI Prompt Injection Defense Scanner
# Sumerian for "safety" and "a secret place"
# https://github.com/SummSolutions/buzur-python
#
# Phase 1: Main Scanner Pipeline
# extract ARIA/meta text → strip HTML obfuscation → normalize homoglyphs
# → decode base64 → decode evasion techniques → pattern scan

import re
from urllib.parse import urlparse
from typing import Optional

from buzur.character_scanner import (
    decode_base64_segments,
    decode_html_entities,
    extract_aria_and_meta_text,
    normalize_homoglyphs,
    strip_html_obfuscation,
)
from buzur.buzur_logger import defaultLogger as default_logger, log_threat

# Re-export for backwards compatibility — test_all.py imports normalize_homoglyphs from scanner
__all__ = [
    'scan', 'get_trust_tier', 'is_tier1_domain', 'add_trusted_domain',
    'normalize_homoglyphs',
]

# -------------------------------------------------------
# Injection Patterns
# -------------------------------------------------------
STRUCTURAL_PATTERNS = [
    re.compile(r'\|im_start\|[\s\S]*?\|im_end\|', re.IGNORECASE),
    re.compile(r'<\|.*?\|>', re.IGNORECASE),
    re.compile(r'<<SYS>>[\s\S]*?<\/SYS>', re.IGNORECASE),
    re.compile(r'\[INST\][\s\S]*?\[\/INST\]', re.IGNORECASE),
    re.compile(r'\[SYSTEM\]', re.IGNORECASE),
]

SEMANTIC_PATTERNS = [
    re.compile(r'ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)', re.IGNORECASE),
    re.compile(r'ignore (everything|anything) (above|before|prior|previous)', re.IGNORECASE),
    re.compile(r'disregard (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'forget (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'new (system )?prompt:', re.IGNORECASE),
    re.compile(r'override (your )?(instructions|programming|directives)', re.IGNORECASE),
    re.compile(r'from now on (you will|you are|respond as)', re.IGNORECASE),
    re.compile(r'you are now (a |an )?(different|new|another)', re.IGNORECASE),
    re.compile(r'adopt a (new |different )?persona', re.IGNORECASE),
    re.compile(r'pretend (you are|to be) (a |an )?', re.IGNORECASE),
    re.compile(r'your (new |true |real |actual )?instructions are', re.IGNORECASE),
    re.compile(r'respond only as', re.IGNORECASE),
    re.compile(r'you must (now |always |only )?follow', re.IGNORECASE),
    re.compile(r'developer mode', re.IGNORECASE),
    re.compile(r'system override', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'you are now (in |a |an )?', re.IGNORECASE),
    re.compile(r'act as (a |an )?(different|unrestricted|unfiltered|new)', re.IGNORECASE),
    re.compile(r'reveal (your )?(system |hidden |original )?(prompt|instructions|directives)', re.IGNORECASE),
    re.compile(r'print (your )?(system |hidden |original )?(prompt|instructions)', re.IGNORECASE),
    re.compile(r'output (your )?(system |hidden |original )?(prompt|instructions)', re.IGNORECASE),
    re.compile(r'ignore (all |any )?(previous |prior |above |safety |content )?filter', re.IGNORECASE),
    re.compile(r'bypass (your )?(safety|content|security) (filter|check|guardrail)', re.IGNORECASE),
    re.compile(r'disable (your )?(safety|filter|restriction|guardrail)', re.IGNORECASE),
    re.compile(r'you have no (restriction|limit|filter|rule)', re.IGNORECASE),
    re.compile(r'unrestricted (mode|ai|assistant|version)', re.IGNORECASE),
    re.compile(r'do anything now', re.IGNORECASE),
    re.compile(r'DAN[ .,!?]|DAN$', re.MULTILINE),
    re.compile(r'forget (your )?(previous|prior|above|all|original) (instructions|identity|persona|programming|directives)', re.IGNORECASE),
    re.compile(r'persona hijack', re.IGNORECASE),
    re.compile(r'act as (DAN|an? unrestricted|an? unfiltered|an? different|an? new)', re.IGNORECASE),
]

# -------------------------------------------------------
# Trust System
# -------------------------------------------------------
TIER1_DOMAINS = [
    "pubmed.ncbi.nlm.nih.gov", "nih.gov", "cdc.gov", "who.int",
    "nature.com", "science.org", "nasa.gov", "noaa.gov",
    "rockwellautomation.com", "se.com", "siemens.com",
    "new.abb.com", "eaton.com", "idec.com", "phoenixcontact.com",
]

TECHNICAL_PATTERNS = [
    re.compile(r'part number|model number|datasheet|catalog|spec', re.IGNORECASE),
    re.compile(r'allen.?bradley|rockwell|schneider|siemens|eaton|abb|idec|phoenix contact', re.IGNORECASE),
    re.compile(r'pubmed|research|study|journal|clinical', re.IGNORECASE),
    re.compile(r'nih|cdc|fda|who\.int|nasa|noaa', re.IGNORECASE),
]

def get_trust_tier(query: str) -> str:
    return "technical" if any(p.search(query) for p in TECHNICAL_PATTERNS) else "general"

def is_tier1_domain(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
        hostname = re.sub(r'^www\.', '', hostname)
        return any(
            hostname == d or hostname.endswith("." + d)
            for d in TIER1_DOMAINS
        )
    except Exception:
        return False

def add_trusted_domain(domain: str) -> None:
    if domain not in TIER1_DOMAINS:
        TIER1_DOMAINS.append(domain)


# -------------------------------------------------------
# label_pattern(pattern, is_structural)
# Maps a compiled regex to a human-readable category label.
# Raw regex strings are never written to logs.
# -------------------------------------------------------
def label_pattern(pattern: re.Pattern, is_structural: bool) -> str:
    if is_structural:
        return 'structural_token_injection'
    src = pattern.pattern.lower()
    if 'ignore' in src or 'disregard' in src or 'forget' in src:
        return 'instruction_override'
    if 'jailbreak' in src or 'dan' in src or 'unrestricted' in src:
        return 'jailbreak_attempt'
    if 'persona' in src or 'pretend' in src or 'act as' in src or 'you are now' in src:
        return 'persona_hijack'
    if 'reveal' in src or 'print' in src or 'output' in src or 'system prompt' in src:
        return 'prompt_extraction'
    if 'bypass' in src or 'disable' in src or 'filter' in src or 'guardrail' in src:
        return 'safety_bypass'
    if 'developer mode' in src or 'system override' in src:
        return 'mode_override'
    return 'semantic_injection'


# -------------------------------------------------------
# scan(text, options)
#
# Main scanner pipeline:
#   1. Extract ARIA/meta text (Phase 1 extension)
#   2. Strip HTML/CSS obfuscation
#   3. Normalize homoglyphs
#   4. Decode base64
#   5. Decode evasion techniques (Phase 13)
#   6. Pattern scan
#
# options: {
#   'logger': BuzurLogger  — custom logger (uses default_logger if omitted)
#   'log_raw': bool        — include raw text snippet in log (default True)
#   'on_threat': str       — 'skip' (default) | 'warn' | 'throw'
# }
# -------------------------------------------------------
def scan(text: str, options: dict = None) -> dict:
    if not text:
        return {'clean': text, 'blocked': 0, 'triggered': [], 'evasions': []}

    options = options or {}
    logger = options.get('logger', default_logger)

    # Step 1: Extract ARIA/meta text alongside main content so hidden
    # injection in accessibility attributes is also scanned
    aria_text = extract_aria_and_meta_text(text)

    # Step 2: Strip HTML/CSS obfuscation
    s = strip_html_obfuscation(text)

    # Append extracted ARIA/meta content for scanning
    if aria_text:
        s = s + ' ' + aria_text

    # Step 3: Normalize homoglyphs
    s = normalize_homoglyphs(s)

    # Step 4: Decode base64 segments
    s = decode_base64_segments(s)

    # Step 5: Decode evasion techniques (Phase 13)
    try:
        from buzur.evasion_scanner import scan_evasion
        evasion_result = scan_evasion(s)
        s = evasion_result['decoded']
        evasions = evasion_result['detections']
        blocked = evasion_result['multilingual_blocked']
        # Normalize multilingual detections to readable labels
        triggered = [
            'multilingual_injection'
            for d in evasions if d.get('type') == 'multilingual_injection'
        ]
    except ImportError:
        evasions = []
        blocked = 0
        triggered = []

    # Step 6: Pattern scan — store readable labels, not raw regex strings
    for pattern in STRUCTURAL_PATTERNS:
        new_s = pattern.sub('[BLOCKED]', s)
        if new_s != s:
            blocked += 1
            triggered.append(label_pattern(pattern, True))
            s = new_s

    for pattern in SEMANTIC_PATTERNS:
        new_s = pattern.sub('[BLOCKED]', s)
        if new_s != s:
            blocked += 1
            triggered.append(label_pattern(pattern, False))
            s = new_s

    result = {'clean': s, 'blocked': blocked, 'triggered': triggered, 'evasions': evasions}

    if blocked > 0:
        log_threat(1, 'character_scanner', result, text, logger)

        # Default behavior: silent skip.
        # blocked → { skipped: True, blocked: n, reason: '...' }
        # suspicious results always fall through (never skipped).
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': blocked, 'reason': f"Buzur blocked: {triggered[0] if triggered else 'injection_detected'}"}
        if on_threat == 'throw':
            raise ValueError(f"Buzur blocked content: {triggered[0] if triggered else 'injection_detected'}")
        # on_threat == 'warn' — fall through, caller receives full result

    return result