from rest_framework import serializers
from .models import Scan, ScanResult

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = (
            'commit_hash', 'branch', 'risk_type',
            'file_path', 'snippet', 'timestamp', 'remediation'
        )

class ScanSerializer(serializers.ModelSerializer):
    results = ScanResultSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = ('scan_id', 'repo_url', 'status', 'created_at', 'completed_at', 'results')
