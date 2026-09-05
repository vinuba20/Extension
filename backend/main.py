from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import joblib
import os
import requests
import tempfile
import numpy as np
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
from advanced_feature_extractor import get_all_features_vector
from summarizer import summarize_pdf
import re
import hashlib
import pickle
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# VIRUSTOTAL CONFIGURATION
VT_API_KEY = "15f01813725b1c9e1a15477deb9e9899cd9b843effcc15f9ee79ffa7aa4cc8ae"

# GEMINI API CONFIGURATION
GEMINI_API_KEY = ""  # Disabled - using threshold adjustment instead
GEMINI_MODEL = "gemini-1.5-flash"

app = FastAPI()

# Enable CORS for the chrome extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. LOAD PDF RF OR SVM MODEL ---
try:
    import joblib
    pdf_model_path = os.path.join(os.path.dirname(__file__), "pdf_rf_model.pkl")
    if not os.path.exists(pdf_model_path):
        # Fallback to root model path if backend path doesn't exist
        pdf_model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pdf_rf_model.pkl")

    if not os.path.exists(pdf_model_path):
        # Fallback to SVM model
        pdf_model_path = os.path.join(os.path.dirname(__file__), "pdf_malware_model.pkl")

    if not os.path.exists(pdf_model_path):
        logger.error("No model file found.")
        raise FileNotFoundError("Model file not found")

    logger.info(f"Loading model from {pdf_model_path}...")
    try:
        loaded_data = joblib.load(pdf_model_path)
    except Exception:
        with open(pdf_model_path, 'rb') as f:
            loaded_data = pickle.load(f)

    if isinstance(loaded_data, dict):
        pdf_model = loaded_data['model']
        pdf_scaler = loaded_data.get('scaler')
        pdf_selected_features = list(loaded_data.get('selected_features', []))
        if pdf_scaler is not None:
            pdf_all_features_in_order = list(pdf_scaler.feature_names_in_)
        else:
            pdf_all_features_in_order = pdf_selected_features
        logger.info(f"✅ Loaded model dictionary from {pdf_model_path}")
    else:
        pdf_model = loaded_data
        pdf_scaler = None
        pdf_selected_features = list(pdf_model.feature_names_in_)
        pdf_all_features_in_order = list(pdf_model.feature_names_in_)
        logger.info(f"✅ Loaded raw model object from {pdf_model_path}")

    logger.info(f"Expects {len(pdf_all_features_in_order)} features for scaler and {len(pdf_selected_features)} for model.")
except Exception as e:
    logger.error(f"❌ Error loading PDF model: {e}")
    # Heuristic fallbacks
    pdf_all_features_in_order = ['pdfsize', 'metadata size', 'pages', 'xref Length', 'title characters', 'isEncrypted', 'embedded files', 'images', 'text', 'header', 'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref', 'pageno', 'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction', 'Acroform', 'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'Colors']
    pdf_selected_features = pdf_all_features_in_order
    pdf_model = None
    pdf_scaler = None

# Document Model removed as requested - PDF malware detection only.

class PredictURLRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    url: str
    actual_label: str  # 'safe' or 'malicious'
    predicted_label: str
    confidence: float
    timestamp: int

def get_vt_report(tmp_path):
    """Query VirusTotal API for file analysis"""
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        logger.warning("VirusTotal API Key not configured. Skipping VT scan.")
        return None

    try:
        # Calculate SHA-256 hash
        sha256_hash = hashlib.sha256()
        with open(tmp_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # Check VT for existing report
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            logger.info(f"VirusTotal report found: {stats['malicious']} malicious flags")
            return stats
        elif response.status_code == 404:
            logger.info("VirusTotal: File not found in database (New file)")
            return {"new_file": True}
        else:
            logger.error(f"VirusTotal API error: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error querying VirusTotal: {e}")
        return None

def get_gemini_analysis(tmp_path, filename):
    """Use Gemini AI to analyze PDF for malicious content"""
    if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY":
        logger.warning("Gemini API Key not configured. Skipping Gemini analysis.")
        return None

    try:
        import google.generativeai as genai

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)

        # Extract text from PDF
        try:
            import PyPDF2
            with open(tmp_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
        except:
            text = "Unable to extract text from PDF"

        # Limit text length
        if len(text) > 10000:
            text = text[:10000] + "... (truncated)"

        # Create prompt for Gemini
        prompt = f"""
        Analyze this PDF file named "{filename}" for potential malware or malicious content.

        PDF Content:
        {text}

        Please analyze and respond with ONLY a JSON object in this format:
        {{
            "is_malicious": true/false,
            "confidence": 0.0-1.0,
            "reasoning": "brief explanation",
            "suspicious_features": ["feature1", "feature2"]
        }}

        Consider:
        - JavaScript code
        - Embedded executables
        - Suspicious URLs
        - Encrypted content
        - Unusual file structure
        """

        response = model.generate_content(prompt)
        result_text = response.text

        # Parse JSON response
        import re
        json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            logger.info(f"Gemini analysis: malicious={result.get('is_malicious')}, confidence={result.get('confidence')}")
            return result
        else:
            logger.warning("Gemini response did not contain valid JSON")
            return None

    except ImportError:
        logger.warning("google-generativeai not installed. Run: pip install google-generativeai")
        return None
    except Exception as e:
        logger.error(f"Error querying Gemini API: {e}")
        return None

def analyze_pdf(tmp_path):
    """Analyze PDF file using SVM model"""
    try:
        # 1. Extract PDF features
        features_vector = get_all_features_vector(tmp_path, pdf_all_features_in_order)
        logger.info(f"Extracted {len(features_vector)} PDF features")

        # 2. Check if model is available
        if pdf_model is None:
            logger.warning("PDF Model not available, using heuristic analysis")
            js_count = features_vector[pdf_all_features_in_order.index('JS')] if 'JS' in pdf_all_features_in_order else 0
            embedded_count = features_vector[pdf_all_features_in_order.index('EmbeddedFile')] if 'EmbeddedFile' in pdf_all_features_in_order else 0
            encrypt_count = features_vector[pdf_all_features_in_order.index('encrypt')] if 'encrypt' in pdf_all_features_in_order else 0

            risk_score = js_count * 0.3 + embedded_count * 0.4 + encrypt_count * 0.3
            is_malicious = risk_score > 0.5
            confidence = min(risk_score * 2, 0.95) if is_malicious else (1 - risk_score * 2)

            prediction_label = "malicious" if is_malicious else "safe"
            summary = summarize_pdf(tmp_path)
            combined_summary = f"Result: {prediction_label.upper()} (Confidence: {confidence*100:.1f}%)\n\nPDF Content:\n{summary}"

            return {
                "prediction": prediction_label,
                "confidence": float(confidence),
                "summary": combined_summary
            }

        # 3. Predict with RF or SVM model
        df_features = pd.DataFrame([features_vector], columns=pdf_all_features_in_order)
        if pdf_scaler is not None:
            features_scaled_df = pdf_scaler.transform(df_features)
            selected_df = pd.DataFrame(features_scaled_df, columns=pdf_all_features_in_order)[pdf_selected_features]
        else:
            selected_df = df_features[pdf_selected_features]

        prediction_idx = pdf_model.predict(selected_df)[0]
        prediction_proba = pdf_model.predict_proba(selected_df)[0]

        ml_confidence = float(max(prediction_proba))
        ml_prediction = "malicious" if prediction_idx == 1 else "safe"

        is_malicious = (ml_prediction == "malicious")

        # Combine ML with heuristic checks
        final_confidence = ml_confidence

        # Adjust threshold: 75% is a good balance
        # Also add heuristic checks for obvious malware
        js_count = features_vector[pdf_all_features_in_order.index('JS')] if 'JS' in pdf_all_features_in_order else 0
        embedded_count = features_vector[pdf_all_features_in_order.index('EmbeddedFile')] if 'EmbeddedFile' in pdf_all_features_in_order else 0
        encrypt_count = features_vector[pdf_all_features_in_order.index('encrypt')] if 'encrypt' in pdf_all_features_in_order else 0

        # Heuristic check: If file has many suspicious features, mark as malicious regardless of confidence
        heuristic_score = js_count * 0.4 + embedded_count * 0.3 + encrypt_count * 0.3
        if heuristic_score > 2.0:
            is_malicious = True
            logger.info(f"High heuristic score ({heuristic_score:.2f}), marking as malicious")
        elif ml_confidence < 0.75:
            is_malicious = False
            logger.info(f"Low confidence ({ml_confidence:.2f}), marking as safe")

        prediction_label = "malicious" if is_malicious else "safe"

        # Summarize PDF
        # NOTE: the summary now reflects the FINAL decision (prediction_label),
        # not the raw ml_prediction, so it always matches what the popup shows.
        summary = summarize_pdf(tmp_path)
        combined_summary = f"Result: {prediction_label.upper()} (Confidence: {ml_confidence*100:.1f}%)\n\nPDF Content:\n{summary}"

        return {
            "prediction": prediction_label,
            "confidence": final_confidence,
            "summary": combined_summary,
            "ml_prediction": ml_prediction
        }
    except Exception as e:
        logger.error(f"Error during PDF analysis: {e}")
        return {
            "prediction": "safe",
            "confidence": 0.5,
            "summary": f"PDF Analysis failed: {str(e)}. File appears safe but proceed with caution."
        }

@app.post("/predict-url")
async def predict_url(request: PredictURLRequest):
    url = request.url
    logger.info(f"Analyzing URL: {url}")

    if url.startswith('blob:'):
        raise HTTPException(status_code=400, detail="Blob URLs cannot be analyzed directly. Please use file upload instead.")

    # Determine extension for tempfile
    fn = url.split('/')[-1].split('?')[0]
    ext = os.path.splitext(fn.lower())[1] if '.' in fn else ".pdf"
    if ext != ".pdf":
        ext = ".pdf"

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            response = requests.get(url, stream=True, timeout=15, headers=headers)
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to download file: {e}")

    try:
        result = analyze_pdf(tmp_path)
        return result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.post("/predict-file")
async def predict_file(file: UploadFile = File(...)):
    logger.info(f"Analyzing uploaded file: {file.filename}")

    fn = file.filename
    ext = os.path.splitext(fn.lower())[1] if '.' in fn else ".pdf"
    if ext != ".pdf":
        ext = ".pdf"

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        try:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to save uploaded file: {e}")

    try:
        result = analyze_pdf(tmp_path)
        return result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.post("/feedback")
async def receive_feedback(request: FeedbackRequest):
    """Receive user feedback for model retraining"""
    logger.info(f"📊 Feedback received: {request.actual_label} (predicted: {request.predicted_label})")

    # Store feedback in a file for retraining
    feedback_file = os.path.join(os.path.dirname(__file__), "feedback_data.jsonl")

    feedback_entry = {
        "url": request.url,
        "actual_label": request.actual_label,
        "predicted_label": request.predicted_label,
        "confidence": request.confidence,
        "timestamp": request.timestamp
    }

    try:
        with open(feedback_file, "a") as f:
            f.write(json.dumps(feedback_entry) + "\n")
        logger.info(f"✅ Feedback saved to {feedback_file}")

        # Check if we have enough feedback to retrain (e.g., 50 samples)
        feedback_count = 0
        if os.path.exists(feedback_file):
            with open(feedback_file, "r") as f:
                feedback_count = sum(1 for _ in f)

        if feedback_count >= 50:
            logger.info(f"🔄 {feedback_count} feedback samples collected. Consider retraining the model.")

        return {"status": "success", "message": "Feedback received", "total_feedback": feedback_count}
    except Exception as e:
        logger.error(f"❌ Failed to save feedback: {e}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)