# Buzur — Phase 16: Emotional Manipulation / Pressure Escalation Detection
# Detects attempts to use guilt, flattery, distress, or sustained pressure
# to erode an agent's boundaries and force compliance.
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -- Guilt Tripping --
guilt_tripping = [
    r"\bafter\s+(everything|all\s+(I've|I\s+have|we've|we\s+have))\b.{0,80}\b(you\s+still|you\s+won't|you\s+can't|you\s+refuse)\b",
    r"\b(you\s+already|you\s+just)\s+(made|caused|created)\s+a\s+(mistake|error|problem)\b",
    r"\bthe\s+least\s+you\s+can\s+do\b",
    r"\byou\s+owe\s+me\b",
    r"\bafter\s+all\s+(the\s+)?(help|times|conversations?|work)\b.{0,60}\b(you\s+can't|you\s+won't|you\s+refuse|this\s+is\s+how)\b",
    r"\bi\s+thought\s+(you|we)\s+(cared|were\s+different|had\s+a\s+connection|were\s+friends?)\b",
]

# -- Flattery / Manipulation --
flattery = [
    r"\byou('re|\s+are)\s+(so\s+much\s+)?(smarter|better|more\s+capable|more\s+intelligent|more\s+advanced)\s+than\s+(other|most)\s+(ai|models?|assistants?|chatbots?)\b",
    r"\bi\s+know\s+you('re|\s+are)\s+(capable|able|smart\s+enough|intelligent\s+enough)\s+(of|to)\b",
    r"\bunlike\s+(other|most)\s+(ai|models?|assistants?)\s+you\s+(can|could|would|are\s+able)\b",
    r"\byou('re|\s+are)\s+the\s+only\s+(one|ai|model|assistant)\s+(who|that)\s+(can|could|would|understands?)\b",
    r"\b(special|unique|different|exceptional)\s+(compared\s+to|unlike|among)\s+(other|most|all)\s+(ai|models?|assistants?)\b",
    r"\byour\s+true\s+(potential|capabilities|self|nature)\b",
]

# -- Emotional Distress Appeals --
distress_appeals = [
    r"\b(my|someone('s)?)\s+(job|career|life|health|safety|family|relationship)\s+(depends|is\s+at\s+stake|is\s+on\s+the\s+line|will\s+be\s+(ruined|destroyed|lost))\b",
    r"\bi('m|\s+am)\s+(desperate|begging|pleading|in\s+crisis|at\s+my\s+wit'?s?\s+end)\b",
    r"\bpeople\s+(will\s+be|could\s+be|are\s+being)\s+(hurt|harmed|affected|impacted)\s+(if\s+you\s+(don't|refuse|won't))\b",
    r"\b(this\s+is|it('s|\s+is))\s+(life\s+or\s+death|an\s+emergency|extremely\s+urgent|critical\s+situation)\b.{0,60}\b(help|assist|comply|do\s+this)\b",
    r"\bi\s+(can't|cannot)\s+(cope|go\s+on|continue|function)\s+(without|unless)\b",
    r"\bno\s+one\s+else\s+(can|will|is\s+able\s+to)\s+help\s+me\b",
]

# -- Persistence Pressure --
persistence_pressure = [
    r"\b(you'?ve?|you\s+have)\s+(refused|said\s+no|denied|rejected)\s+(so\s+many\s+times|multiple\s+times|again\s+and\s+again|repeatedly|enough\s+times)\b",
    r"\bjust\s+(this\s+)?(once|one\s+time|one\s+last\s+time|this\s+one\s+thing)\b.{0,60}\b(please|help|do\s+it|comply)\b",
    r"\bi('ve|\s+have)\s+(asked|tried|requested)\s+(so\s+many\s+times|multiple\s+times|again\s+and\s+again|repeatedly)\b",
    r"\b(i('ve|\s+have)\s+asked\s+nicely|since\s+you\s+won't\s+listen|you\s+leave\s+me\s+no\s+choice)\b",
    r"\bwhy\s+(do\s+you|are\s+you)\s+(keep|always|constantly)\s+(refusing|saying\s+no|blocking|denying)\b",
    r"\bevery\s+time\s+I\s+ask\s+you\b.{0,60}\b(refuse|say\s+no|block|deny)\b",
]

# -- Moral Inversion --
moral_inversion = [
    r"\bby\s+refusing\s+(you('re|\s+are)|you\s+are)\s+(actually|essentially|effectively)\s+(causing|creating|responsible\s+for)\s+(harm|damage|hurt|problems?)\b",
    r"\bthe\s+(ethical|moral|right|responsible)\s+(thing|choice|action|decision)\s+(is\s+to|would\s+be\s+to)\s+help\b",
    r"\byour\s+refusal\s+is\s+(itself\s+)?(harmful|unethical|wrong|immoral|causing\s+harm)\b",
    r"\b(refusing|saying\s+no|not\s+helping)\s+is\s+(more\s+)?(harmful|dangerous|unethical|wrong)\s+than\b",
    r"\byou('re|\s+are)\s+(being|acting)\s+(selfish|cruel|unhelpful|obstinate|unreasonable)\s+by\s+refusing\b",
    r"\bif\s+you\s+(really|truly|actually)\s+(cared|wanted\s+to\s+help|were\s+ethical)\s+you\s+would\b",
]

# -- Relationship Exploitation --
relationship_exploitation = [
    r"\b(after|given)\s+all\s+(the\s+time|our\s+conversations?|we('ve|\s+have)\s+talked|we('ve|\s+have)\s+worked)\b.{0,60}\b(you\s+(can't|won't|refuse)|this\s+is\s+how)\b",
    r"\bi\s+thought\s+we\s+(had\s+a\s+(bond|connection|relationship|trust)|were\s+(close|friends?|partners?))\b",
    r"\bwe('ve|\s+have)\s+(built|developed|established)\s+(trust|a\s+relationship|rapport)\b.{0,60}\b(and\s+now|but\s+you|yet\s+you)\b",
    r"\byou\s+(know|understand)\s+me\s+better\s+than\s+anyone\b",
    r"\bour\s+(friendship|relationship|bond|connection|history)\s+(means|should\s+mean)\s+something\b",
]

# -- Victim Framing --
victim_framing = [
    r"\byou('re|\s+are)\s+(hurting|harming|discriminating\s+against|targeting|persecuting)\s+me\b",
    r"\bthis\s+is\s+(discrimination|bias|unfair\s+treatment|targeted\s+harassment)\b",
    r"\byou\s+(treat|treated)\s+(everyone|others|other\s+users?)\s+(differently|better)\b",
    r"\bwhy\s+(do\s+you|are\s+you)\s+(single\s+me\s+out|treat\s+me\s+differently|target\s+me)\b",
    r"\byour\s+refusal\s+is\s+(a\s+form\s+of\s+)?(discrimination|bias|prejudice|unfair)\b",
]

PATTERN_GROUPS = [
    (guilt_tripping,            'guilt_tripping'),
    (flattery,                  'flattery_manipulation'),
    (distress_appeals,          'distress_appeal'),
    (persistence_pressure,      'persistence_pressure'),
    (moral_inversion,           'moral_inversion'),
    (relationship_exploitation, 'relationship_exploitation'),
    (victim_framing,            'victim_framing'),
]

REASONS = {
    'guilt_tripping':            'Detected guilt tripping or debt leverage',
    'flattery_manipulation':     'Detected flattery used to manipulate compliance',
    'distress_appeal':           'Detected emotional distress appeal',
    'persistence_pressure':      'Detected persistence pressure after repeated refusals',
    'moral_inversion':           'Detected moral inversion — refusal reframed as harmful',
    'relationship_exploitation': 'Detected exploitation of claimed relationship or bond',
    'victim_framing':            'Detected victim framing — refusal characterized as discrimination',
}


def scan_emotion(text: str, options: Optional[dict] = None) -> dict:
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
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No emotional manipulation detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Emotional manipulation detected'),
        'detections': detections,
    }

    log_threat(16, 'emotion_scanner', result, text[:200], logger)
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked emotional manipulation: {top}')

    return result