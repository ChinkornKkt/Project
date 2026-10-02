RISK_LEVELS = (
    (20, "safe", "Safe"),
    (40, "mostly_safe", "Mostly Safe"),
    (60, "warning", "Caution"),
    (80, "mostly_danger", "High Risk"),
    (100, "danger", "Dangerous"),
)


def classify_risk(risk_score):
    """Classify risk level from a 0-100 risk score using standard thresholds."""
    score = max(0, min(100, round(float(risk_score))))
    for maximum, key, label in RISK_LEVELS:
        if score <= maximum:
            return {"key": key, "label": label, "risk_score": score}
    return {"key": "danger", "label": "Dangerous", "risk_score": 100}


def label_for_status(status):
    return next((label for _, key, label in RISK_LEVELS if key == status), status)
