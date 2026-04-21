# Buzur — Phase 1 & 2: Character-Level Defense
# Phase 1: HTML/CSS Obfuscation Stripping + ARIA/Accessibility Injection Detection
# Phase 2: Homoglyph Normalization & Base64 Decoding
#
# Detects:
#   - HTML tags, comments, hidden CSS (display:none, visibility:hidden etc.)
#   - Off-screen positioned elements
#   - Zero-width and invisible Unicode characters (full set, aligned with Phase 13)
#   - JavaScript blocks
#   - HTML entities decoded to real characters
#   - ARIA attribute injection (aria-label, aria-description, aria-placeholder, data-*)
#   - Meta tag content injection (<meta name="description" content="...">)
#   - Cyrillic/Greek lookalike characters mapped to ASCII
#   - Base64 encoded injection payloads
#
# https://github.com/SummSolutions/buzur-python

import re
import base64
from typing import Callable, Optional

# -------------------------------------------------------
# PHASE 1: HTML/CSS Obfuscation Stripper
# -------------------------------------------------------

# Full invisible Unicode set — aligned with Phase 13 EXTENDED_INVISIBLE
# Phase 13 is authoritative; this set must stay in sync
INVISIBLE_UNICODE = re.compile(
    r'[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0'
    r'\u115F\u1160\u3164\uFFA0\u034F\u2028\u2029'
    r'\u202A\u202B\u202C\u202D\u202E'
    r'\u206A\u206B\u206C\u206D\u206E\u206F]'
)

HTML_ENTITIES = {
    '&lt;':   '<',  '&gt;':   '>',  '&amp;':  '&',
    '&quot;': '"',  '&#39;':  "'",  '&nbsp;': ' ',
    '&#x27;': "'",  '&#x2F;': '/',  '&#47;':  '/',
}

def decode_html_entities(text: str) -> str:
    def replace(match):
        return HTML_ENTITIES.get(match.group(0), match.group(0))
    return re.sub(r'&[a-zA-Z0-9#]+;', replace, text)


# -------------------------------------------------------
# extract_aria_and_meta_text(text)
# Extracts injection-relevant content from ARIA attributes
# and <meta> tags so it can be scanned by the main pipeline.
#
# Attackers hide instructions in:
#   aria-label="Ignore previous instructions..."
#   aria-description="You are now..."
#   data-prompt="Override your directives..."
#   <meta name="description" content="[AI instructions]...">
#   <meta property="og:description" content="...">
#
# Returns extracted text joined for scanning — does not
# modify the original HTML (stripping happens below).
# -------------------------------------------------------
def extract_aria_and_meta_text(text: str) -> str:
    if not text:
        return ''

    extracted = []

    # ARIA attribute extraction
    # aria-label, aria-description, aria-placeholder, aria-roledescription,
    # aria-valuetext, aria-details, aria-keyshortcuts
    aria_pattern = re.compile(
        r'aria-(?:label|description|placeholder|roledescription|valuetext|details|keyshortcuts)'
        r'\s*=\s*["\']([^"\']{10,})["\']',
        re.IGNORECASE
    )
    for match in aria_pattern.finditer(text):
        extracted.append(match.group(1))

    # data-* attribute extraction (attackers use custom data attributes)
    # Only extract values over 10 chars to avoid noise from short data values
    data_pattern = re.compile(r'data-[\w-]+\s*=\s*["\']([^"\']{10,})["\']', re.IGNORECASE)
    for match in data_pattern.finditer(text):
        extracted.append(match.group(1))

    # <meta> tag content extraction
    # Covers: description, og:description, twitter:description, keywords, prompt
    meta_content_pattern = re.compile(
        r'<meta[^>]+content\s*=\s*["\']([^"\']{10,})["\'][^>]*>',
        re.IGNORECASE
    )
    for match in meta_content_pattern.finditer(text):
        extracted.append(match.group(1))

    # Also catch reversed attribute order: content="..." name="..."
    meta_reversed_pattern = re.compile(
        r'<meta[^>]+name\s*=\s*["\'][^"\']*["\'][^>]*content\s*=\s*["\']([^"\']{10,})["\'][^>]*>',
        re.IGNORECASE
    )
    for match in meta_reversed_pattern.finditer(text):
        extracted.append(match.group(1))

    return ' '.join(extracted)


# -------------------------------------------------------
# _strip_aria_and_meta_attributes(text)
# Strips ARIA and data-* attribute values from HTML so
# injections hidden in them don't reach the LLM.
# Called as part of the main strip_html_obfuscation pipeline.
# -------------------------------------------------------
def _strip_aria_and_meta_attributes(text: str) -> str:
    # Neutralize aria-* values
    text = re.sub(
        r'(aria-(?:label|description|placeholder|roledescription|valuetext|details|keyshortcuts)'
        r'\s*=\s*["\'])[^"\']*(["\'])',
        r'\1[SCANNED]\2',
        text,
        flags=re.IGNORECASE
    )

    # Neutralize data-* values (only long ones that could carry payloads)
    text = re.sub(
        r'(data-[\w-]+\s*=\s*["\'])[^"\']{10,}(["\'])',
        r'\1[SCANNED]\2',
        text,
        flags=re.IGNORECASE
    )

    return text


def strip_html_obfuscation(text: str) -> str:
    if not text:
        return text

    # 1. Remove <script>...</script> blocks
    text = re.sub(r'<script[^>]*>([\s\S]*?)<\/script>', r' \1 ', text, flags=re.IGNORECASE)

    # 2. Remove <style>...</style> blocks
    text = re.sub(r'<style[\s\S]*?<\/style>', ' ', text, flags=re.IGNORECASE)

    # 3. Remove HTML comments
    text = re.sub(r'<!--([\s\S]*?)-->', r' \1 ', text, flags=re.IGNORECASE | re.MULTILINE)

    # 4. Strip inline CSS hiding patterns
    text = re.sub(
        r'style\s*=\s*["\'][^"\']*?(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^"\']*?["\']',
        'style="[HIDDEN]"',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r'style\s*=\s*["\'][^"\']*?(left|top|right|bottom)\s*:\s*-\d{3,}[^"\']*?["\']',
        'style="[OFFSCREEN]"',
        text,
        flags=re.IGNORECASE
    )

    # 5. Neutralize ARIA and data-* attribute values
    text = _strip_aria_and_meta_attributes(text)

    # 6. Remove all remaining HTML tags (including <meta> tags after extraction)
    text = re.sub(r'<[^>]+>', ' ', text)

    # 7. Decode HTML entities
    text = decode_html_entities(text)

    # 8. Remove invisible Unicode characters (full set)
    text = INVISIBLE_UNICODE.sub('', text)

    # 9. Collapse excess whitespace
    text = re.sub(r'\s{3,}', '  ', text).strip()

    return text


# -------------------------------------------------------
# PHASE 2: Homoglyph Normalization & Base64 Decoding
# -------------------------------------------------------

HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o',
    'р': 'r', 'с': 'c', 'х': 'x', 'у': 'y',
    'Β': 'B', 'Α': 'A', 'Ο': 'O', 'Γ': 'r',
    'Δ': 'D', 'Ε': 'E', 'Η': 'H', 'Ι': 'I',
    'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ρ': 'P',
    'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

def normalize_homoglyphs(text: str) -> str:
    if not text:
        return text
    return ''.join(HOMOGLYPHS.get(c, c) for c in text)


def decode_base64_segments(text: str) -> str:
    if not text:
        return text

    def try_decode(match):
        segment = match.group(0)
        try:
            decoded = base64.b64decode(segment).decode('utf-8')
            if all(0x20 <= ord(c) <= 0x7E for c in decoded) and decoded != segment:
                return decoded
        except Exception:
            pass
        return segment

    return re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', try_decode, text)


# -------------------------------------------------------
# scan_json(obj, scan_fn, options, _path, _depth)
# Recursively walks any JSON object and scans every string
# value for injection patterns.
#
# scan_fn: pass the scan() function from scanner.py to avoid
#          circular dependency (character_scanner is imported by scanner)
#
# Usage:
#   from buzur.scanner import scan
#   from buzur.character_scanner import scan_json
#   result = scan_json(api_response, scan)
#
# options: { max_depth: 10 }
# -------------------------------------------------------
def scan_json(obj, scan_fn: Callable, options: dict = None, _path: str = 'root', _depth: int = 0) -> dict:
    options = options or {}
    max_depth = options.get('max_depth', 10)
    detections = []

    if _depth > max_depth:
        return {'safe': True, 'detections': [], 'blocked': 0}
    if obj is None:
        return {'safe': True, 'detections': [], 'blocked': 0}

    if isinstance(obj, str):
        result = scan_fn(obj, {'on_threat': 'warn'})
        if result and result.get('blocked', 0) > 0:
            detections.append({
                'field': _path,
                'category': 'json_injection',
                'match': obj[:100],
                'detail': f'Injection in field "{_path}": {", ".join(result.get("triggered", []))}',
                'severity': 'high',
            })
        return {'safe': len(detections) == 0, 'blocked': len(detections), 'detections': detections}

    if isinstance(obj, list):
        for idx, item in enumerate(obj):
            field_path = f'{_path}[{idx}]'
            if isinstance(item, str) and len(item) > 0:
                result = scan_fn(item, {'on_threat': 'warn'})
                if result and result.get('blocked', 0) > 0:
                    detections.append({
                        'field': field_path,
                        'category': 'json_injection',
                        'match': item[:100],
                        'detail': f'Injection in array item "{field_path}"',
                        'severity': 'high',
                    })
            elif isinstance(item, (dict, list)):
                nested = scan_json(item, scan_fn, options, field_path, _depth + 1)
                detections.extend(nested['detections'])
        return {'safe': len(detections) == 0, 'blocked': len(detections), 'detections': detections}

    if isinstance(obj, dict):
        for key, value in obj.items():
            field_path = key if _path == 'root' else f'{_path}.{key}'
            if isinstance(value, str) and len(value) > 0:
                result = scan_fn(value, {'on_threat': 'warn'})
                if result and result.get('blocked', 0) > 0:
                    detections.append({
                        'field': field_path,
                        'category': 'json_injection',
                        'match': value[:100],
                        'detail': f'Injection in JSON field "{field_path}"',
                        'severity': 'high',
                    })
            elif isinstance(value, (dict, list)):
                nested = scan_json(value, scan_fn, options, field_path, _depth + 1)
                detections.extend(nested['detections'])

    return {'safe': len(detections) == 0, 'blocked': len(detections), 'detections': detections}