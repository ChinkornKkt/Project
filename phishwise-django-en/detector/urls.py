from django.urls import path

from .views import get_scan_history, scan_url


urlpatterns = [
    path('api/v1/scan/', scan_url, name='scan-url'),
    path('api/v1/history/', get_scan_history, name='scan-history'),
]