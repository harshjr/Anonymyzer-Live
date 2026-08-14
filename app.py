from pathlib import Path
import shutil
import uuid

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


app = FastAPI(
    title="PII Document Anonymizer",
    description="Upload TXT, DOCX, or PDF files and receive anonymized versions.",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
OUTPUT_DIR = Path("outputs")

UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


@app.get("/")
def root():
    return {
        "status": "running",
        "service": "PII Anonymizer"
    }


@app.post("/anonymize")
async def anonymize_document(
    file: UploadFile = File(...)
):

    suffix = Path(file.filename).suffix.lower()

    if suffix not in [".txt", ".docx", ".pdf"]:
        raise HTTPException(
            status_code=400,
            detail="Only TXT, DOCX and PDF files are supported"
        )

    unique_id = str(uuid.uuid4())

    input_path = (
        UPLOAD_DIR /
        f"{unique_id}_{file.filename}"
    )

    output_path = (
        OUTPUT_DIR /
        f"{Path(file.filename).stem}_redacted{suffix}"
    )

    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(
            file.file,
            buffer
        )

    engine = PIIEngine()
    mapper = SyntheticMapper()

    if suffix == ".txt":
        process_txt(
            input_path,
            output_path,
            engine,
            mapper
        )

    elif suffix == ".docx":
        process_docx(
            input_path,
            output_path,
            engine,
            mapper
        )

    elif suffix == ".pdf":
        process_pdf(
            input_path,
            output_path,
            engine,
            mapper
        )

    return FileResponse(
        str(output_path),
        filename=output_path.name,
        media_type="application/octet-stream"
    )