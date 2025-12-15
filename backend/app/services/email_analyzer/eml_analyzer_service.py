import httpx
from fastapi import UploadFile
from typing import Any, Dict

from app.core.config import settings

EML_ANALYZER_URL = getattr(
    settings, "eml_analyzer_url", "https://eml-analyzer.herokuapp.com/api/analyze/file"
)


async def analyze_eml_file(file: UploadFile) -> Dict[str, Any]:
    """
    Send the uploaded EML file to the external analyzer and return raw JSON.
    """
    async with httpx.AsyncClient(timeout=60) as client:
        content = await file.read()
        files = {
            "file": (
                file.filename or "email.eml",
                content,
                file.content_type or "message/rfc822",
            )
        }
        resp = await client.post(EML_ANALYZER_URL, files=files)
        resp.raise_for_status()
        return resp.json()
