import uuid
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Scan
from .serializers import ScanSerializer
from .tasks import run_scan_task

class ScanCreateView(APIView):
    def post(self, request):
        repo_url = request.data.get('repo_url')
        if not repo_url:
            return Response({"error": "Repository URL is required."}, status=status.HTTP_400_BAD_REQUEST)
        # Basic validation: allow only GitHub URLs
        if "github.com" not in repo_url:
            return Response({"error": "Only GitHub repositories are supported."}, status=status.HTTP_400_BAD_REQUEST)
        
        scan_id = uuid.uuid4().hex
        scan = Scan.objects.create(scan_id=scan_id, repo_url=repo_url, status='queued')
        
        # Trigger the asynchronous scan task
        run_scan_task.delay(scan_id)
        
        return Response({"scan_id": scan_id, "status": scan.status}, status=status.HTTP_202_ACCEPTED)

class ScanDetailView(APIView):
    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(scan_id=scan_id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_200_OK)
