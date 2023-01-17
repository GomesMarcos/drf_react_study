from io import StringIO
from csv import reader

from rest_framework.exceptions import ValidationError

from .serializers import VulnerabilitySerializer


def sanitize_file(file):
    # decoded_file = file.read().decode()
    # decoded_file.split("\n").pop(0)
    # decoded_file.pop(-1)
    # return decoded_file

    decoded_file = file.read().decode()
    return reader(StringIO(decoded_file))


def reader_to_dict(author, row: reader) -> dict:
    return {
        "author": author or 1,
        "asset_hostname": row[0],
        "asset_ip_address": row[1],
        "title": row[2],
        "severity": row[3][0],
        "cvss": row[4],
        "publication_date": row[5],
    }


def validate_file(author, csv_file):
    while csv_file:
        row = next(csv_file)

        if "ASSET - HOSTNAME" in row[0]:
            continue

        vulnerability_serializer = VulnerabilitySerializer(
            data=reader_to_dict(author=author, row=row)
        )

        try:
            vulnerability_serializer.is_valid(raise_exception=True)
        except ValidationError as exc:
            return {"error": exc.detail, "file_line": csv_file.line_num}
    return {}


def save_file(author, csv_file):
    while csv_file:
        row = next(csv_file)

        if "ASSET - HOSTNAME" in row[0]:
            continue

        vulnerability_serializer = VulnerabilitySerializer(
            data=reader_to_dict(author=author, row=row)
        )
        vulnerability_serializer.save()
