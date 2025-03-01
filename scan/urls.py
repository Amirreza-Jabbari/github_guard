from django.urls import path
from .views import ScanCreateView, ScanDetailView

urlpatterns = [
    path('scan/', ScanCreateView.as_view(), name='scan-create'),
    path('scan/<str:scan_id>/', ScanDetailView.as_view(), name='scan-detail'),
]
