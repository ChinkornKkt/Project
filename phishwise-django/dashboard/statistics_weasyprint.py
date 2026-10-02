from .weasyprint_runtime import font_context, write_pdf


def _chart_context(data):
    total = max(data.get("total_scans", 0), 1)
    safe = data.get("safe_count", 0) * 100 / total
    warning = data.get("warning_count", 0) * 100 / total
    danger = data.get("danger_count", 0) * 100 / total
    values = data.get("trend_values") or [0]
    labels = data.get("trend_labels") or ["-"]
    maximum = max(max(values), 1)
    step = 440 / max(len(values), 1)
    bars = []
    for index, (label, value) in enumerate(zip(labels, values)):
        height = value * 105 / maximum
        bars.append({
            "label": label, "value": value, "x": 38 + index * step,
            "height": height, "y": 132 - height, "text_y": 126 - height,
        })
    circumference = 301.59
    return {
        "safe_dash": f"{safe * circumference / 100:.2f} {circumference:.2f}",
        "warning_dash": f"{warning * circumference / 100:.2f} {circumference:.2f}",
        "warning_offset": f"{-safe * circumference / 100:.2f}",
        "danger_dash": f"{danger * circumference / 100:.2f} {circumference:.2f}",
        "danger_offset": f"{-(safe + warning) * circumference / 100:.2f}",
        "trend_bars": bars,
    }


def build_statistics_pdf(data):
    context = {**font_context(), **data, **_chart_context(data)}
    return write_pdf("pdf/statistics_report.html", context)
