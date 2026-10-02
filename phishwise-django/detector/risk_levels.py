RISK_LEVELS = (
    (20, "safe", "ปลอดภัย"),
    (40, "mostly_safe", "ค่อนข้างปลอดภัย"),
    (60, "warning", "ควรระวัง"),
    (80, "mostly_danger", "มีแนวโน้มอันตราย"),
    (100, "danger", "อันตราย"),
)


def classify_risk(risk_score):
    """จัดระดับจากคะแนนความเสี่ยง 0-100 ด้วยเกณฑ์กลางของระบบ"""
    score = max(0, min(100, round(float(risk_score))))
    for maximum, key, label in RISK_LEVELS:
        if score <= maximum:
            return {"key": key, "label": label, "risk_score": score}
    return {"key": "danger", "label": "อันตราย", "risk_score": 100}


def label_for_status(status):
    return next((label for _, key, label in RISK_LEVELS if key == status), status)
