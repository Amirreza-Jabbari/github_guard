from django.db import models

class Scan(models.Model):
    scan_id = models.CharField(max_length=64, unique=True)
    repo_url = models.URLField()
    status = models.CharField(
        max_length=20,
        choices=(
            ('queued', 'Queued'),
            ('in_progress', 'In Progress'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
        ),
        default='queued'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.scan_id

class ScanResult(models.Model):
    scan = models.ForeignKey(Scan, related_name='results', on_delete=models.CASCADE)
    commit_hash = models.CharField(max_length=40)
    branch = models.CharField(max_length=100)
    risk_type = models.CharField(max_length=100)
    file_path = models.CharField(max_length=255)
    snippet = models.TextField()
    timestamp = models.DateTimeField()
    remediation = models.TextField()

    def __str__(self):
        return f"{self.risk_type} in {self.file_path} at {self.commit_hash}"
