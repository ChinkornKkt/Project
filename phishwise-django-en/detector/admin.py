from django.contrib import admin

from .models import ScanHistory


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = (
        'url',
        'score',
        'status',
        'ai_risk_score',
        'is_blacklisted',
        'google_safe',
        'timestamp',
    )
    search_fields = ('url', 'status')
