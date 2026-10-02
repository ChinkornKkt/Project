from django.db import migrations


def classify_existing_scans(apps, schema_editor):
    ScanHistory = apps.get_model("detector", "ScanHistory")
    for scan in ScanHistory.objects.all().iterator():
        risk = max(0, min(100, int(scan.ai_risk_score)))
        if risk <= 20:
            status = "safe"
        elif risk <= 40:
            status = "mostly_safe"
        elif risk <= 60:
            status = "warning"
        elif risk <= 80:
            status = "mostly_danger"
        else:
            status = "danger"
        if scan.status != status:
            scan.status = status
            scan.save(update_fields=["status"])


class Migration(migrations.Migration):
    dependencies = [("detector", "0002_scanhistory_source_type_scanhistory_user")]

    operations = [migrations.RunPython(classify_existing_scans, migrations.RunPython.noop)]
