import os
import tempfile
import shutil
from celery import shared_task
from django.utils import timezone
from git import Repo
from .models import Scan
from .risk_scanner import scan_repository

@shared_task
def run_scan_task(scan_id):
    try:
        scan_obj = Scan.objects.get(scan_id=scan_id)
        scan_obj.status = 'in_progress'
        scan_obj.save()
        
        # Create a temporary directory for cloning the repository
        temp_dir = tempfile.mkdtemp()
        repo_dir = os.path.join(temp_dir, "repo")
        
        # Clone the public GitHub repository
        Repo.clone_from(scan_obj.repo_url, repo_dir)
        
        # Run the scanning engine on the cloned repository
        scan_repository(repo_dir, scan_obj)
        
        # Update scan status to completed
        scan_obj.status = 'completed'
        scan_obj.completed_at = timezone.now()
        scan_obj.save()
        
    except Exception as e:
        scan_obj.status = 'failed'
        scan_obj.save()
        raise e
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)
