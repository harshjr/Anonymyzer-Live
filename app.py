import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from pii_anonymizer import (
    PIIEngine,
    SyntheticMapper,
    process_txt,
    process_docx,
    process_pdf
)

# Global engine instance initialized on startup or on first call
engine: PIIEngine | None = None


def get_engine() -> PIIEngine:
    global engine
    if engine is None:
        engine = PIIEngine()
    return engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm NLP model & Presidio engine on server boot
    get_engine()
    yield


app = FastAPI(
    title="PII Document Anonymizer API",
    description="Upload TXT, DOCX, or PDF files and receive anonymized versions.",
    version="1.0.0",
    lifespan=lifespan
)

# Correct CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
OUTPUT_DIR = Path("outputs")
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


@app.get("/")
def root():
    index_file = Path(__file__).parent / "index.html"
    if index_file.exists():
        return FileResponse(index_file, media_type="text/html")
    return {
        "status": "online",
        "service": "PII Document Anonymizer API",
        "supported_formats": [".txt", ".docx", ".pdf"]
    }


@app.get("/api")
def api_status():
    return {
        "status": "online",
        "service": "PII Document Anonymizer API",
        "supported_formats": [".txt", ".docx", ".pdf"]
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/anonymize")
async def anonymize_document(
    file: UploadFile = File(...)
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded.")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in [".txt", ".docx", ".pdf"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{suffix}'. Only TXT, DOCX, and PDF are supported."
        )

    unique_id = uuid.uuid4().hex[:8]
    clean_stem = Path(file.filename).stem
    input_path = UPLOAD_DIR / f"{unique_id}_{file.filename}"
    output_path = OUTPUT_DIR / f"{unique_id}_{clean_stem}_redacted{suffix}"

    try:
        # Save incoming upload
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Fresh mapper for each document (guarantees intra-document consistency)
        mapper = SyntheticMapper()
        pii_engine = get_engine()

        if suffix == ".txt":
            process_txt(input_path, output_path, pii_engine, mapper)
        elif suffix == ".docx":
            process_docx(input_path, output_path, pii_engine, mapper)
        elif suffix == ".pdf":
            process_pdf(input_path, output_path, pii_engine, mapper)

        if not output_path.exists():
            raise HTTPException(status_code=500, detail="Failed to generate redacted output.")

        download_filename = f"{clean_stem}_redacted{suffix}"

        return FileResponse(
            path=str(output_path),
            filename=download_filename,
            media_type="application/octet-stream"
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Processing error: {str(e)}")

    finally:
        # Clean up temporary uploaded raw file to protect privacy & disk space
        if input_path.exists():
            input_path.unlink(missing_ok=True)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port)