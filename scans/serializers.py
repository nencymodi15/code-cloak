from rest_framework import serializers
from .models import Scan

class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            'id', 
            'file_name', 
            'file', 
            'file_size', 
            'sha256_hash', 
            'risk_score', 
            'status', 
            'created_at', 
            'updated_at'
        ]
        read_only_fields = ['id', 'file_name','file_size', 'sha256_hash', 'risk_score', 'status', 'created_at', 'updated_at']
    
    def create(self, validated_data):
        # Automatically populate file_name from the uploaded file if not explicitly provided
        uploaded_file = validated_data.get('file')
        if uploaded_file and not validated_data.get('file_name'):
            validated_data['file_name'] = uploaded_file.name
        return super().create(validated_data)