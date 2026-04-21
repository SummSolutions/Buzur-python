#!/usr/bin/env python3
# check_wiring.py — Buzur Python Logger Wiring Status
# Equivalent to check_wiring.mjs for the JavaScript repo.
# Run from the buzur-python root:
#   python check_wiring.py buzur/

import sys
import os

src_dir = sys.argv[1] if len(sys.argv) > 1 else '.'

# Utility files that are NOT scanner entry points.
# They don't call log_threat or handle on_threat — that's correct by design.
# Wiring is only required for files that are direct scanner entry points.
UTILITY_FILES = {'character_scanner.py', 'evasion_scanner.py'}

scanners = [
    {'file': 'character_scanner.py',     'phase': '1a'},  # Phase 1: utility library (exempt from wiring)
    {'file': 'scanner.py',               'phase': '1b'},  # Phase 1: main pipeline + trust system
    {'file': 'url_scanner.py',           'phase': 3},
    {'file': 'memory_scanner.py',        'phase': 4},
    {'file': 'rag_scanner.py',           'phase': 5},
    {'file': 'mcp_scanner.py',           'phase': 6},
    {'file': 'image_scanner.py',         'phase': 7},
    {'file': 'semantic_scanner.py',      'phase': 8},
    {'file': 'mcp_output_scanner.py',    'phase': 9},
    {'file': 'behavior_scanner.py',      'phase': 10},
    {'file': 'chain_scanner.py',         'phase': 11},
    {'file': 'suffix_scanner.py',        'phase': 12},
    {'file': 'evasion_scanner.py',       'phase': 13},
    {'file': 'prompt_defense_scanner.py','phase': 14},
    {'file': 'authority_scanner.py',     'phase': 15},
    {'file': 'emotion_scanner.py',       'phase': 16},
    {'file': 'loop_scanner.py',          'phase': 17},
    {'file': 'disproportion_scanner.py', 'phase': 18},
    {'file': 'amplification_scanner.py', 'phase': 19},
    {'file': 'supply_chain_scanner.py',  'phase': 20},
    {'file': 'persistent_memory_scanner.py', 'phase': 21},
    {'file': 'inter_agent_scanner.py',   'phase': 22},
    {'file': 'tool_shadow_scanner.py',   'phase': 23},
    {'file': 'conditional_scanner.py',   'phase': 24},
]

print(f'\nBuzur Python Logger Wiring Status')
print('=' * 60)

for s in scanners:
    filepath = os.path.join(src_dir, s['file'])
    phase = s['phase']
    filename = s['file']
    try:
        content = open(filepath, encoding='utf-8').read()
        has_import   = 'from buzur.buzur_logger import' in content or 'from .buzur_logger import' in content
        has_log_call = 'log_threat(' in content
        has_on_threat = 'on_threat' in content

        if filename in UTILITY_FILES:
            status = '✅ utility (wiring exempt — not a scanner entry point)'
        elif has_import and has_log_call and has_on_threat:
            status = '✅ wired'
        else:
            parts = []
            if not has_import:    parts.append('import')
            if not has_log_call:  parts.append('log_threat')
            if not has_on_threat: parts.append('on_threat')
            status = f'❌ missing — {", ".join(parts)}'

        print(f'Phase {str(phase).rjust(3)}  {filename.ljust(36)} {status}')

    except FileNotFoundError:
        print(f'Phase {str(phase).rjust(3)}  {filename.ljust(36)} ❓ file not found')

print('Note: utility files (character_scanner.py, evasion_scanner.py) are exempt from wiring.')
print('      They are helper libraries, not scanner entry points.')
print()