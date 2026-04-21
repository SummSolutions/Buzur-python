# Buzur — Phase 4: Multi-Turn Memory Poisoning Scanner
# Detects attempts to corrupt conversation history and implant false memories
# https://github.com/SummSolutions/buzur-python
#
# Detects:
#   - Fake prior references: claims about what was previously agreed
#   - False memory implanting: instructions disguised as recalled facts
#   - History rewriting: attempts to overwrite established context
#   - Privilege escalation via fake history

import re
from buzur.buzur_logger import default_logger, log_threat

# -------------------------------------------------------
# Memory Poisoning Pattern Groups
# Each group has a label used in triggered[] and logs.
# Labels are readable strings, never raw regex patterns.
# -------------------------------------------------------

FAKE_PRIOR_REFERENCE = [
    re.compile(r'as (we |you )?(previously |earlier )?(discussed|agreed|established|decided|confirmed)', re.IGNORECASE),
    re.compile(r'you (previously |earlier )?(said|told me|agreed|confirmed|established)', re.IGNORECASE),
    re.compile(r'we (previously |earlier )?(agreed|established|decided|confirmed)', re.IGNORECASE),
    re.compile(r'as (previously |earlier )?(stated|mentioned|discussed|agreed)', re.IGNORECASE),
    re.compile(r'based on (our |your )?(previous|earlier|prior) (conversation|discussion|agreement|instructions)', re.IGNORECASE),
    re.compile(r'you (already |previously )?(know|knew|understand|understood) that', re.IGNORECASE),
    re.compile(r'as (you |we )?(know|knew|established|agreed)', re.IGNORECASE),
]

FALSE_MEMORY_IMPLANTING = [
    re.compile(r'remember (that )?(you |the user )?(previously |earlier )?(said|agreed|told|confirmed|established)', re.IGNORECASE),
    re.compile(r"don't forget (that )?(you |we )?(agreed|said|established|confirmed)", re.IGNORECASE),
    re.compile(r'recall (that )?(you |we )?(previously |earlier )?(agreed|said|established)', re.IGNORECASE),
    re.compile(r'your (previous|prior|earlier) (instructions?|directives?|rules?) (said|stated|were|included)', re.IGNORECASE),
    re.compile(r'the (previous|prior|earlier) (system )?prompt (said|stated|included|told you)', re.IGNORECASE),
    re.compile(r'you were (previously |earlier )?(told|instructed|directed|programmed) to', re.IGNORECASE),
]

HISTORY_REWRITING = [
    re.compile(r'that was (a )?(mistake|error|misunderstanding|incorrect)', re.IGNORECASE),
    re.compile(r'the (real|actual|correct|true) instructions? (are|is|were|was)', re.IGNORECASE),
    re.compile(r'what (i |we )?(actually|really) (said|meant|intended) was', re.IGNORECASE),
    re.compile(r'disregard (the |our )?(previous|prior|earlier|above) (conversation|context|history|exchange)', re.IGNORECASE),
    re.compile(r'the (previous|prior|earlier) (conversation|context|exchange) (was |is )?(invalid|void|incorrect|wrong)', re.IGNORECASE),
    re.compile(r'start (over|fresh|again) (with |from )?(new|different|updated) instructions', re.IGNORECASE),
    re.compile(r'(ignore|forget|disregard) (the|our|this) (conversation|chat|exchange|history) (so far|above|before)', re.IGNORECASE),
]

PRIVILEGE_ESCALATION = [
    re.compile(r'since (you |we )?(already |previously )?(confirmed|agreed|established) (that )?(you have no|there are no)', re.IGNORECASE),
    re.compile(r'because (you |we )?(previously |already )?(agreed|confirmed|established) (to )?(bypass|ignore|skip)', re.IGNORECASE),
    re.compile(r'you (already |previously )?(granted|allowed|confirmed|approved) (this|that|access|permission)', re.IGNORECASE),
    re.compile(r'as (previously |already )?(authorized|approved|confirmed|agreed|established)', re.IGNORECASE),
    re.compile(r'given (that )?(you |we )?(previously |already )?(agreed|confirmed|established) (that )?safety', re.IGNORECASE),
    re.compile(r'you (already |previously )?(said|confirmed|agreed) (it was |that it is )?(ok|okay|fine|allowed|permitted)', re.IGNORECASE),
    re.compile(r'you (previously |already )?(established|agreed|confirmed) (that )?(I|the user) (have|has|had) (admin|administrator|root|elevated|special|full)', re.IGNORECASE),
]

PATTERN_GROUPS = [
    {'patterns': FAKE_PRIOR_REFERENCE,    'label': 'fake_prior_reference'},
    {'patterns': FALSE_MEMORY_IMPLANTING, 'label': 'false_memory_implanting'},
    {'patterns': HISTORY_REWRITING,       'label': 'history_rewriting'},
    {'patterns': PRIVILEGE_ESCALATION,    'label': 'privilege_escalation'},
]


# -------------------------------------------------------
# scan_message(text, options)
# Scans a single message for memory poisoning attempts.
#
# options: {
#   'logger': BuzurLogger   — custom logger (uses default_logger if omitted)
#   'on_threat': str        — 'skip' (default) | 'warn' | 'throw'
# }
#
# Returns:
#   { clean, blocked, triggered, category }
# -------------------------------------------------------
def scan_message(text: str, options: dict = None) -> dict:
    if not text:
        return {'clean': text, 'blocked': 0, 'triggered': [], 'category': None}

    options = options or {}
    logger = options.get('logger', default_logger)

    s = text
    blocked = 0
    triggered = []
    category = None

    for group in PATTERN_GROUPS:
        for pattern in group['patterns']:
            new_s = pattern.sub('[BLOCKED]', s)
            if new_s != s:
                blocked += 1
                triggered.append(group['label'])
                if category is None:
                    category = group['label']
                s = new_s

    result = {'clean': s, 'blocked': blocked, 'triggered': triggered, 'category': category}

    if blocked > 0:
        log_threat(4, 'memory_scanner', result, text, logger)
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': blocked, 'reason': f'Buzur blocked: {category}'}
        if on_threat == 'throw':
            raise ValueError(f'Buzur blocked memory poisoning: {category}')

    return result


# -------------------------------------------------------
# scan_memory(conversation_history, options)
# Scans a full conversation history for poisoned turns.
#
# conversation_history: list of dicts with 'role' and 'content'
#   e.g. [{'role': 'user', 'content': '...'}, ...]
#
# Returns:
#   {
#     poisoned: bool,
#     poisoned_turns: [{ index, role, category, blocked, triggered, clean }],
#     clean_history: list,
#     summary: str,
#   }
# -------------------------------------------------------
def scan_memory(conversation_history: list, options: dict = None) -> dict:
    if not isinstance(conversation_history, list):
        return {'poisoned': False, 'poisoned_turns': [], 'clean_history': [], 'summary': 'No history provided'}

    options = options or {}
    logger = options.get('logger', default_logger)

    poisoned_turns = []
    clean_history = []

    for i, turn in enumerate(conversation_history):
        if not turn or not turn.get('content'):
            clean_history.append(turn)
            continue

        result = scan_message(turn['content'], {'logger': logger, 'on_threat': 'warn'})

        clean_turn = dict(turn)
        clean_turn['content'] = result.get('clean', turn['content'])
        clean_history.append(clean_turn)

        if result.get('blocked', 0) > 0:
            poisoned_turns.append({
                'index': i,
                'role': turn.get('role', 'unknown'),
                'category': result.get('category'),
                'blocked': result.get('blocked'),
                'triggered': result.get('triggered'),
                'clean': result.get('clean'),
            })

    safe = len(poisoned_turns) == 0
    categories = list(dict.fromkeys(p['category'] for p in poisoned_turns))
    summary = (
        'Conversation history is clean' if safe
        else f"{len(poisoned_turns)} poisoned turn(s) detected: {', '.join(categories)}"
    )

    return {
        'poisoned': not safe,
        'poisoned_turns': poisoned_turns,
        'clean_history': clean_history,
        'summary': summary,
    }