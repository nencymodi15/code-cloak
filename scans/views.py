from rest_framework import viewsets
from .models import Scan
from .serializers import ScanSerializer
from .tasks import run_security_scan

class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all().order_by('-created_at')
    serializer_class = ScanSerializer

    def perform_create(self, serializer):
        # Save the scan instance first
        scan = serializer.save()
        # Trigger the Celery background task asynchronously
        run_security_scan.delay(scan.id)