import os, json, pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

SEVERITY_SCORES = {"Critical":10, "High":7, "Medium":4, "Low":2, "Info":0}
TYPE_WEIGHTS    = {
    "SQL Injection":1.2, "Broken Access Control":1.1,
    "Authentication Failure":1.1, "Security Misconfiguration":0.9,
}
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'risk_model.pkl')

def findings_to_features(findings):
    """Convert a list of findings to a feature vector for the ML model."""
    counts = {s: 0 for s in SEVERITY_SCORES}
    for f in findings:
        counts[f.get('severity', 'Info')] += 1
    total = max(len(findings), 1)
    return [[
        counts['Critical'] / total,
        counts['High']     / total,
        counts['Medium']   / total,
        counts['Low']      / total,
        len(findings),
    ]]

def rule_based_score(findings):
    """Fallback rule-based scorer used for training data generation."""
    if not findings: return 0
    total = sum(
        SEVERITY_SCORES.get(f.get('severity','Low'),2) *
        TYPE_WEIGHTS.get(f.get('type',''),1.0)
        for f in findings
    )
    return round(total / len(findings), 2)

def train_model():
    """Generate synthetic training data and train a RandomForest."""
    import random
    X, y = [], []
    random.seed(42)
    severities = ['Critical','High','Medium','Low','Info']
    for _ in range(500):
        n = random.randint(1, 20)
        fake = [{'severity': random.choice(severities),
                 'type': random.choice(list(TYPE_WEIGHTS.keys()))}
                for _ in range(n)]
        X.append(findings_to_features(fake)[0])
        score = rule_based_score(fake)
        if   score >= 9: label = 4
        elif score >= 7: label = 3
        elif score >= 4: label = 2
        elif score  > 0: label = 1
        else:            label = 0
        y.append(label)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, 'wb') as fh:
        pickle.dump(clf, fh)
    print('[risk_scorer] Model trained and saved to models/risk_model.pkl')
    return clf

def load_or_train():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as fh:
            return pickle.load(fh)
    return train_model()

LABELS = {4:'CRITICAL', 3:'HIGH', 2:'MEDIUM', 1:'LOW', 0:'SAFE'}

def score_findings(findings):
    """Main function called by app.py — returns score + risk level."""
    if not findings:
        return {'score': 0, 'level': 'SAFE', 'total': 0}
    clf  = load_or_train()
    feat = findings_to_features(findings)
    pred = clf.predict(feat)[0]
    raw  = rule_based_score(findings)
    return {'score': raw, 'level': LABELS[pred], 'total': len(findings)}

if __name__ == '__main__':
    train_model()
    test = [{'severity':'Critical','type':'SQL Injection'},
            {'severity':'High','type':'Broken Access Control'}]
    print(score_findings(test))
