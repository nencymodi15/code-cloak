from django.contrib import admin
from .models import Scan, FileSignature

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'file_name', 'file_size', 'risk_score', 'status', 'created_at')
    readonly_fields = ('id', 'file_size', 'sha256_hash', 'risk_score', 'status', 'created_at', 'updated_at')

@admin.register(FileSignature)
class FileSignatureAdmin(admin.ModelAdmin):
    list_display = ('extension', 'file_category', 'default_risk_score', 'magic_bytes_hex')
    search_fields = ('extension', 'file_category')