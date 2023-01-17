from django.urls import include, path

from .views import VulnerabilityAPIView


urlpatterns = [
    path("", VulnerabilityAPIView.as_view(), name="vulnerabilities"),
    path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
]
