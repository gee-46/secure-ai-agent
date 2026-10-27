"""Safe text extraction for classification previews.

Uploaded documents are treated as untrusted input: this module only reads
text content for display/classification purposes. It never executes
embedded scripts, macros, or instructions found inside a document, and it
never sends document content anywhere outside the local process.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_PREVIEW_CHARS = 20_000


@dataclass(frozen=True)
class ExtractionResult:
    text: str
    supported: bool
    note: str


def extract_text_preview(filename: str, data: bytes) -> ExtractionResult:
    lower = filename.lower()

    if lower.endswith(".txt") or lower.endswith(".md") or lower.endswith(".csv"):
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return ExtractionResult(text="", supported=False, note="File is not valid UTF-8 text.")
        return ExtractionResult(text=text[:MAX_PREVIEW_CHARS], supported=True, note="Extracted plain text.")

    if lower.endswith(".pdf"):
        try:
            from pypdf import PdfReader
            import io

            reader = PdfReader(io.BytesIO(data))
            chunks = []
            for page in reader.pages[:20]:
                chunks.append(page.extract_text() or "")
            text = "\n".join(chunks).strip()
        except Exception:
            return ExtractionResult(
                text="", supported=False,
                note="Could not extract text from this PDF (it may be scanned, encrypted, or corrupted).",
            )
        if not text:
            return ExtractionResult(text="", supported=False, note="PDF contained no extractable text.")
        return ExtractionResult(text=text[:MAX_PREVIEW_CHARS], supported=True, note="Extracted text from PDF.")

    return ExtractionResult(
        text="", supported=False,
        note="Automatic text extraction is not supported for this file type. "
             "Binary/unsupported files are encrypted as-is without content classification; "
             "please review and set the classification manually.",
    )
