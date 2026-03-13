POLICIES = {
    'CRITICAL': {
        'action':      'BLOCK',
        'description': 'Immediate threat. Block access and patch now.',
        'priority':    1,
    },
    'HIGH': {
        'action':      'PATCH_IMMEDIATELY',
        'description': 'High risk. Patch within 24 hours.',
        'priority':    2,
    },
    'MEDIUM': {
        'action':      'MONITOR',
        'description': 'Moderate risk. Schedule fix within 7 days.',
        'priority':    3,
    },
    'LOW': {
        'action':      'LOG',
        'description': 'Low risk. Log and review in next sprint.',
        'priority':    4,
    },
    'SAFE': {
        'action':      'NONE',
        'description': 'No vulnerabilities detected.',
        'priority':    5,
    },
}

FINDING_RECOMMENDATIONS = {
    'SQL Injection':             'Use parameterised queries. Never concatenate user input into SQL.',
    'Broken Access Control':     'Add authentication middleware. Verify JWT/session on every route.',
    'Authentication Failure':    'Enforce strong passwords. Add rate limiting and account lockout.',
    'Security Misconfiguration': 'Add missing headers in server config. Remove exposed debug files.',
}

def apply_policy(risk):
    """Called by app.py with the risk dict from score_findings().
    Returns policy action and description. """
    level  = risk.get('level', 'SAFE')
    policy = POLICIES.get(level, POLICIES['SAFE'])
    return {
        'level':       level,
        'action':      policy['action'],
        'description': policy['description'],
        'priority':    policy['priority'],
    }

def get_recommendations(findings):
    """Return one recommendation per unique finding type."""
    recs  = {}
    for f in findings:
        t = f.get('type', '')
        if t and t not in recs:
            recs[t] = FINDING_RECOMMENDATIONS.get(t, 'Review and remediate.')
    return [{'type': t, 'recommendation': r} for t, r in recs.items()]
