from django.contrib import admin
from django.urls import path, include

# from vulnerabilities_analyzer.urls import

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("vulnerabilities_analyzer.urls")),
]
