import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from detector.models import ScanHistory
from detector.risk_levels import classify_risk


DEMO_URL_PREFIX = "https://statistics-demo-"


class Command(BaseCommand):
    help = "Generate mock scan statistics across 6 months for testing"

    def handle(self, *args, **options):
        User = get_user_model()
        users = list(User.objects.filter(is_staff=False, is_active=True).order_by("id"))
        if not users:
            raise CommandError("No active regular users found.")

        # Idempotent: delete existing demo records
        removed, _ = ScanHistory.objects.filter(url__startswith=DEMO_URL_PREFIX).delete()
        rng = random.Random(661463050)
        now = timezone.now()
        sources = ["direct_url", "camera_qr", "image_qr"]
        source_weights = [0.58, 0.23, 0.19]
        locations = ["United States", "Singapore", "Japan", "Thailand", "United Kingdom"]
        records = []

        # Gradual trend over 180 days
        for days_ago in range(180, -1, -1):
            recent_factor = 1 + ((180 - days_ago) // 45)
            daily_count = rng.randint(1, 3) + rng.randint(0, recent_factor)
            if days_ago % 17 == 0:
                daily_count += 3

            for daily_index in range(daily_count):
                user = users[(days_ago + daily_index + rng.randrange(len(users))) % len(users)]
                risk = rng.choices(
                    population=[rng.randint(3, 20), rng.randint(21, 40), rng.randint(41, 60),
                                rng.randint(61, 80), rng.randint(81, 98)],
                    weights=[42, 23, 18, 11, 6],
                    k=1,
                )[0]
                level = classify_risk(risk)
                source = rng.choices(sources, weights=source_weights, k=1)[0]
                timestamp = now - timedelta(
                    days=days_ago,
                    hours=rng.randint(0, 20),
                    minutes=rng.randint(0, 59),
                )
                sequence = len(records) + 1
                records.append(
                    ScanHistory(
                        user=user,
                        url=f"{DEMO_URL_PREFIX}{sequence:04d}.test/check/{user.id}",
                        source_type=source,
                        score=100 - risk,
                        status=level["key"],
                        ai_risk_score=risk,
                        ssl_title="Demo SSL Certificate" if risk <= 60 else "Not Secure",
                        ssl_sub="Mocked for statistics",
                        domain_age=f"{rng.randint(1, 12)} months",
                        domain_sub="Sample research data",
                        is_blacklisted=risk >= 81,
                        google_safe=risk < 81,
                        location=rng.choice(locations),
                        has_redirection=risk >= 61 or rng.random() < 0.12,
                        timestamp=timestamp,
                    )
                )

        ScanHistory.objects.bulk_create(records, batch_size=250)
        self.stdout.write(
            self.style.SUCCESS(
                f"Generated {len(records)} mock records for {len(users)} users "
                f"(removed {removed} old mock records)"
            )
        )
