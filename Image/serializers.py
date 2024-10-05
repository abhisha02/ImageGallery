from rest_framework import serializers
from .models import Image

class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ['id', 'title', 'image', 'created_at', 'updated_at', 'order']
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {'image': {'required': False}}  # Make image field optional for updates