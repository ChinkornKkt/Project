"""
Management command: seed_articles
Populate KnowledgeArticle model from ARTICLES list in views.py.
Idempotent based on title as unique key.
"""
from django.core.management.base import BaseCommand
from dashboard.views import ARTICLES
from detector.models import KnowledgeArticle


class Command(BaseCommand):
    help = "Seed KnowledgeArticle from the hardcoded ARTICLES list in views.py"

    def handle(self, *args, **options):
        created = 0
        skipped = 0
        for idx, art in enumerate(ARTICLES):
            content = {
                "sections": art.get("sections", []),
                "key_takeaways": art.get("key_takeaways", []),
            }
            obj, was_created = KnowledgeArticle.objects.get_or_create(
                title=art["title"],
                defaults={
                    "category": art.get("category", "General Security"),
                    "author": art.get("author", "PhishWise Team"),
                    "author_role": art.get("author_role", "Cybersecurity Specialist"),
                    "date": art.get("date", ""),
                    "read_time": art.get("read_time", ""),
                    "desc": art.get("desc", ""),
                    "image": art.get("image", ""),
                    "summary": art.get("summary", ""),
                    "content": content,
                    "status": KnowledgeArticle.STATUS_PUBLISHED,
                    "order": idx,
                },
            )
            if was_created:
                created += 1
                self.stdout.write(f"  + {obj.title}")
            else:
                skipped += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"\nCompleted: created {created} articles, skipped {skipped} (already exist)"
            )
        )
