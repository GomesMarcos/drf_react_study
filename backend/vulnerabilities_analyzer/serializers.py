from rest_framework import serializers

from .models import Vulnerability


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        extra_kwargs = {
            "author": {"write_only": True},
        }
        model = Vulnerability
        fields = [
            "author",
            "title",
            "severity",
            "cvss",
            "publication_date",
            "asset_hostname",
            "asset_ip_address",
            "is_fixed",
        ]


class CSVUploadSerializer(serializers.Serializer):
    csv_file = serializers.FileField()

    class Meta:
        fields = ("csv_file",)
