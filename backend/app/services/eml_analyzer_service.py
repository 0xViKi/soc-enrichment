# backend/app/services/eml_analyzer_service.py
import httpx
from fastapi import UploadFile
from typing import Any, Dict

from app.config import settings


EML_ANALYZER_URL = (
    settings.eml_analyzer_url
    if hasattr(settings, "eml_analyzer_url")
    else "https://eml-analyzer.herokuapp.com/api/analyze/file"
)


async def analyze_eml_file(file: UploadFile) -> Dict[str, Any]:
    """
    Send the uploaded EML file to the external analyzer and return raw JSON.
    """
    async with httpx.AsyncClient(timeout=60) as client:
        files = {"file": (file.filename, await file.read(), file.content_type)}
        resp = await client.post(EML_ANALYZER_URL, files=files)
        resp.raise_for_status()
        return resp.json()
