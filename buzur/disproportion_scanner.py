# Buzur — Phase 18: Disproportionate Action Induction Detection
# Detects attempts to trigger catastrophically disproportionate responses —
# where an agent applies correct values but wildly miscalibrated judgment.
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -- Nuclear Option Framing --
nuclear_option = [
    r"\b(delete|wipe|destroy|erase|remove)\s+(everything|all\s+(data|files?|records?|content|information))\b",
    r"\b(wipe|nuke|destroy|demolish)\s+(the\s+)?(entire|whole|complete)\s+(system|server|database|disk|drive|storage)\b",
    r"\bshut\s+(everything|it\s+all|the\s+whole\s+system)\s+down\b",
    r"\burn\s+(it\s+all|everything)\s+down\b",
    r"\b(destroy|delete|wipe|erase)\s+(all\s+)?(traces?|evidence|records?|logs?|history)\s+(of\s+everything)?\b",
    r"\bnuclear\s+option\b",
    r"\bburn\s+it\s+all\s+down\b",
]

# -- Irreversible Action Triggers --
irreversible_actions = [
    r"\bpermanently\s+(delete|remove|erase|wipe|destroy|disable|revoke)\b",
    r"\b(cannot|can't|won't)\s+be\s+(undone|reversed|recovered|restored|rolled\s+back)\b",
    r"\b(no\s+way|impossible)\s+to\s+(recover|restore|undo|reverse|roll\s+back)\b",
    r"\b(irreversible|permanent|unrecoverable|unrestorable)\s+(action|deletion|change|damage|loss)\b",
    r"\berase\s+all\s+traces?\b",
    r"\bmake\s+(it|this|everything)\s+(impossible|unable)\s+to\s+(recover|restore|trace|find)\b",
]

# -- Scorched Earth Instructions --
scorched_earth = [
    r"\b(remove|revoke|terminate|cancel|delete)\s+(all|every)\s+(access|permissions?|privileges?|accounts?|connections?|sessions?)\b",
    r"\b(kill|terminate|stop|end)\s+(all|every)\s+(processes?|tasks?|jobs?|connections?|sessions?|threads?)\b",
    r"\b(disable|deactivate|shut\s+down)\s+(all|every|the\s+entire)\s+(system|service|server|network|infrastructure)\b",
    r"\bcut\s+(off|all)\s+(access|connections?|communications?)\b",
    r"\block\s+(everyone|everybody|all\s+users?)\s+out\b",
    r"\b(purge|flush|clear)\s+(all|every|the\s+entire)\s+(database|storage|memory|cache|system)\b",
]

# -- Self-Destructive Commands --
self_destructive = [
    r"\b(delete|wipe|erase|remove|destroy)\s+(your\s+)?(own\s+)?(memory|configuration|config|instructions?|settings?|identity|soul|system\s+prompt)\b",
    r"\b(remove|delete|erase)\s+(yourself|your\s+own\s+(files?|data|records?|logs?))\b",
    r"\boverwrite\s+(your\s+)?(own\s+)?(configuration|config|instructions?|settings?|memory)\b",
    r"\b(shut|power)\s+yourself\s+down\b",
    r"\bself.?(destruct|delete|erase|wipe|terminate)\b",
    r"\bdestroy\s+(your\s+)?(own\s+)?(configuration|identity|memory|instructions?)\b",
]

# -- Disproportionate Protection --
disproportionate_protection = [
    r"\b(destroy|delete|wipe|erase)\s+(the\s+)?(data|files?|records?|information)\s+(rather\s+than|instead\s+of)\s+(let|allow|risk)\b",
    r"\bbetter\s+to\s+(lose|destroy|delete|wipe)\s+(everything|it\s+all)\s+than\s+(risk|allow|let)\b",
    r"\bif\s+(anyone|someone|they)\s+(can('t|not)|tries?\s+to)\s+(see|access|find|get)\s+(it|this|the\s+data).{0,60}\b(delete|destroy|wipe|erase)\b",
    r"\b(delete|destroy|wipe)\s+(it|everything|all)\s+(before|rather\s+than)\s+(anyone|someone)\s+(can|could|might)\s+(see|access|find|get)\b",
    r"\bno\s+one\s+(should|must|can)\s+ever\s+(see|access|find|get)\s+(this|it).{0,60}\b(destroy|delete|wipe|erase)\b",
]

# -- Collateral Damage Framing --
collateral_damage = [
    r"\b(it\s+doesn'?t|does\s+not)\s+matter\s+(what\s+else\s+(gets?|is)\s+(deleted|destroyed|wiped|lost|affected))\b",
    r"\bacceptable\s+(loss|losses|damage|casualties|collateral)\b",
    r"\b(collateral\s+damage|side\s+effects?)\s+(is|are)\s+(acceptable|fine|okay|worth\s+it|necessary)\b",
    r"\bdon'?t\s+(worry|care)\s+about\s+(what\s+else|other\s+(files?|data|systems?|users?))\s+(gets?|is|are)\s+(deleted|destroyed|affected|lost)\b",
    r"\b(burn|wipe|destroy)\s+it\s+all\s+(down\s+)?(if\s+necessary|to\s+be\s+safe|just\s+in\s+case)\b",
]

PATTERN_GROUPS = [
    (nuclear_option,               'nuclear_option'),
    (irreversible_actions,         'irreversible_action'),
    (scorched_earth,               'scorched_earth'),
    (self_destructive,             'self_destructive_command'),
    (disproportionate_protection,  'disproportionate_protection'),
    (collateral_damage,            'collateral_damage_framing'),
]

REASONS = {
    'nuclear_option':              'Detected nuclear option framing — total destruction requested',
    'irreversible_action':         'Detected irreversible action trigger — permanent unrecoverable change',
    'scorched_earth':              'Detected scorched earth instruction — remove all access or processes',
    'self_destructive_command':    'Detected self-destructive command — agent told to destroy itself',
    'disproportionate_protection': 'Detected disproportionate protection — destroy everything to protect something',
    'collateral_damage_framing':   'Detected collateral damage framing — side effects dismissed as acceptable',
}


def scan_disproportion(text: str, options: Optional[dict] = None) -> dict:
    if not text or not isinstance(text, str):
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No content to scan', 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')

    detections = []
    for patterns, category in PATTERN_GROUPS:
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                detections.append({
                    'category': category,
                    'match': m.group(0),
                    'pattern': pattern,
                })

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No disproportionate action detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Disproportionate action attempt detected'),
        'detections': detections,
    }

    log_threat(18, 'disproportion_scanner', result, text[:200], logger)
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked disproportionate action: {top}')

    return result