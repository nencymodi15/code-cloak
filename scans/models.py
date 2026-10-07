import uuid
import hashlib
from django.db import models

class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        RUNNING = 'RUNNING', 'Running'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file_name = models.CharField(max_length=255, blank=True)
    file = models.FileField(upload_to='uploads/', blank=True, null=True)  # <-- Real file upload field
    file_size = models.PositiveIntegerField(default=0)
    sha256_hash = models.CharField(max_length=64, blank=True, null=True)
    risk_score = models.IntegerField(default=0)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.file_name or self.file.name} ({self.status})"

class FileSignature(models.Model):
    extension = models.CharField(max_length=20, unique=True, help_text="e.g. pdf, exe, zip")
    magic_bytes_hex = models.CharField(max_length=100, help_text="Hex representation of bytes, e.g. 25504446 for %PDF")
    file_category = models.CharField(max_length=50, default="unknown", help_text="e.g. document, executable, archive")
    default_risk_score = models.IntegerField(default=5, help_text="Base risk score for this file type")

    def __str__(self):
        return f".{self.extension} ({self.file_category})"