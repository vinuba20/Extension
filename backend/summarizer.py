import fitz  # PyMuPDF

def summarize_pdf(pdf_path: str, max_lines: int = 3) -> str:
    """
    Extracts the first few lines of text from a PDF to generate a short summary.
    """
    try:
        doc = fitz.open(pdf_path)
        text = ""
        for page in doc:
            text += page.get_text()
            if len(text.split('\n')) > 10: # Stop if we have enough
                break
        doc.close()
        
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        summary = " ".join(lines[:max_lines])
        
        if not summary:
            return "No readable text content found in the PDF."
            
        if len(summary) > 200:
            summary = summary[:197] + "..."
            
        return summary
    except Exception as e:
        print(f"Error summarizing PDF: {e}")
        return "Unable to extract summary from this PDF."
