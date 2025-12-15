from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.services.email_analyzer.email_report_service import build_email_report

router = APIRouter(prefix="/email", tags=["email-report"])
templates = Jinja2Templates(directory="app/reports/templates")


@router.post("/report", response_class=HTMLResponse)
async def email_report(request: Request, file: UploadFile = File(...)) -> HTMLResponse:
    """
    Thin wrapper: pipeline + context building is in build_email_report().
    """
    try:
        report = await build_email_report(file)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"EML analyzer error: {e}")

    context = {"request": request, **report.context}
    return templates.TemplateResponse(report.template_name, context)