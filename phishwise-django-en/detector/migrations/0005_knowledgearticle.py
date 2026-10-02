import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("detector", "0004_domainstatistic_suspicioussitereport"),
    ]

    operations = [
        migrations.CreateModel(
            name="KnowledgeArticle",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("category", models.CharField(
                    choices=[
                        ("Phishing", "Phishing"),
                        ("Security", "Security"),
                        ("Scams", "Scams"),
                        ("Malware", "Malware"),
                        ("Privacy", "Privacy"),
                    ],
                    max_length=50,
                )),
                ("author", models.CharField(default="PhishWise Team", max_length=100)),
                ("author_role", models.CharField(default="Cybersecurity Specialist", max_length=100)),
                ("date", models.CharField(blank=True, max_length=30)),
                ("read_time", models.CharField(blank=True, max_length=30)),
                ("desc", models.TextField()),
                ("image", models.URLField(blank=True, max_length=500)),
                ("summary", models.TextField(blank=True)),
                ("content", models.JSONField(
                    default=dict,
                    help_text='{"sections": [...], "key_takeaways": [...]}',
                )),
                ("status", models.CharField(
                    choices=[("draft", "ฉบับร่าง"), ("published", "เผยแพร่แล้ว")],
                    default="draft",
                    max_length=20,
                )),
                ("order", models.PositiveIntegerField(default=0, help_text="ลำดับการแสดงผล (น้อย = แสดงก่อน)")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ("order", "-created_at"),
            },
        ),
    ]
