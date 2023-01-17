from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError

from .serializers import VulnerabilitySerializer, CSVUploadSerializer
from .models import Vulnerability
from .utils import sanitize_file, validate_file, save_file


class VulnerabilityAPIView(APIView):
    """
    API view for vulnerabilities
    """

    def get(self, request):
        vulnerabilities = Vulnerability.objects.filter(author=request.user.id)
        serializer = VulnerabilitySerializer(vulnerabilities, many=True)
        permission_classes = [permissions.IsAuthenticated]
        return Response(serializer.data)

    def post(self, request):
        csv_serializer = CSVUploadSerializer(data=request.data)
        csv_serializer.is_valid(raise_exception=True)

        csv_file = sanitize_file(csv_serializer.validated_data["csv_file"])
        csv_file_validate = validate_file(request.user.id, csv_file)

        if not csv_file_validate.get("error"):
            save_file()
            return Response(csv_serializer.data, status=status.HTTP_201_CREATED)

        return Response(
            csv_file_validate,
            status=status.HTTP_400_BAD_REQUEST,
        )
