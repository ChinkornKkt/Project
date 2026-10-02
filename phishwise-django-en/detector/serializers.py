from rest_framework import serializers

from .models import ScanHistory


class ScanRequestSerializer(serializers.Serializer):
    url = serializers.CharField()


class ScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanHistory
        fields = [
            'source_type',
            'url',
            'score',
            'status',
            'ai_risk_score',
            'ssl_title',
            'ssl_sub',
            'domain_age',
            'domain_sub',
            'is_blacklisted',
            'google_safe',
            'location',
            'has_redirection',
            'timestamp',
        ]
