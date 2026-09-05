# PDF Malware Detector

**PDF Malware Detector** is a Chrome Extension developed to detect potentially malicious PDF files before they are saved to the user's system.

The extension intercepts PDF downloads, temporarily holds the file, sends it to a Python-based machine learning backend for analysis, and displays the prediction to the user. Based on the result, the user can safely save, cancel, or block the file.

## Features

* Intercepts PDF downloads in Google Chrome.
* Analyzes PDF files using machine learning.
* Extracts features from PDF documents for malware detection.
* Provides malware prediction and confidence information.
* Temporarily holds PDF files during analysis.
* Allows users to approve or block downloads.
* Provides a user override option for flagged files.
* Supports URL-based analysis as a fallback.
* Collects user feedback for improving the detection model.
* Provides browser notifications for scan results.

## System Architecture

```text
                    ┌─────────────────────┐
                    │     User downloads  │
                    │         PDF         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Chrome Extension  │
                    │  Download Intercept │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Temporary Sandbox   │
                    │   File Storage      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Python Backend    │
                    │    FastAPI API      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ PDF Feature         │
                    │ Extraction          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Machine Learning    │
                    │      Model          │
                    └──────────┬──────────┘
                               │
                     ┌─────────┴─────────┐
                     ▼                   ▼
                  SAFE              MALICIOUS
                     │                   │
                     ▼                   ▼
              Save Download        Block Download
```

## Technologies Used

### Chrome Extension

* JavaScript
* HTML
* CSS
* Chrome Extension Manifest V3

### Backend

* Python
* FastAPI
* PyMuPDF
* Scikit-learn

### Machine Learning

* Random Forest
* PDF feature extraction
* URL-based analysis
* Feedback-based model improvement

## Project Structure

```text
PDF-Malware-Detector/
│
├── backend/
│   ├── main.py
│   ├── advanced_feature_extractor.py
│   ├── summarizer.py
│   ├── retrain_with_feedback.py
│   ├── pdf_malware_model.pkl
│   ├── pdf_rf_model.pkl
│   ├── url_phishing_model.pkl
│   ├── feedback_data.jsonl
│   └── requirements.txt
│
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   ├── style.css
│   └── icon.png
│
├── PDFMalware2022.csv
├── train_and_save_model.py
├── test_malicious.pdf
├── HOW_TO_IMPROVE_ACCURACY.md
└── SETUP_GEMINI.md
```

## How It Works

### 1. PDF Download Detection

The Chrome extension monitors downloads and identifies PDF files based on their file extension, MIME type, or download URL.

### 2. Download Interception

When a PDF is detected, the extension temporarily stops the original download so that the file can be analyzed before being saved.

### 3. PDF Analysis

The PDF is sent to the Python backend through the `/predict-file` API.

The backend extracts relevant characteristics from the PDF and passes them to the trained machine learning model.

### 4. Malware Prediction

The machine learning model predicts whether the PDF is:

* **Safe**
* **Malicious**
* **Error / Unable to Analyze**

The result includes prediction information and confidence.

### 5. User Decision

The extension displays the analysis result and allows the user to:

* Save a safe PDF.
* Block a malicious PDF.
* Cancel the download.
* Download a flagged PDF through a user override.

### 6. Feedback

User decisions can be sent back to the backend through the feedback API. This information can be used to improve the model.

## Backend API

| Endpoint        | Method | Description                  |
| --------------- | ------ | ---------------------------- |
| `/predict-file` | POST   | Analyzes an uploaded PDF     |
| `/predict-url`  | POST   | Analyzes a PDF using its URL |
| `/feedback`     | POST   | Records user feedback        |

## Installation

### Backend

Navigate to the backend directory:

```powershell
cd backend
```

Create a virtual environment:

```powershell
py -m venv venv
```

Activate the environment:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Start the backend:

```powershell
python main.py
```

The backend runs on:

```text
http://localhost:8000
```

### Chrome Extension

1. Open Google Chrome.
2. Navigate to:

```text
chrome://extensions
```

3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the project's `extension` folder.
6. Make sure the Python backend is running.
7. Download a PDF through Chrome to test the extension.

## Testing

The extension can be tested by downloading PDF files through Chrome.

The expected workflow is:

```text
PDF Download
     ↓
Download Intercepted
     ↓
PDF Analysis
     ↓
Machine Learning Prediction
     ↓
Display Result
     ↓
Save / Block / Cancel
```

> Opening a PDF directly from a local folder does not trigger the Chrome download interception mechanism. The PDF should be downloaded through Chrome when testing the complete extension workflow.

## Machine Learning Model

The project uses machine learning to classify PDF files based on extracted document characteristics.

The trained models are stored in the backend as `.pkl` files and loaded by the backend during prediction.

The project also includes functionality for collecting feedback and retraining the model to improve detection performance.

## Future Improvements

* Improve malware detection accuracy.
* Add more advanced PDF security features.
* Improve detection of obfuscated malicious content.
* Add stronger sandbox isolation.
* Support additional document formats.
* Integrate real-time threat intelligence.
* Improve model retraining and evaluation.
* Enhance the Chrome extension interface.

## Disclaimer

This project is developed as a machine-learning-based PDF security and malware detection system for educational and research purposes. It should not be considered a replacement for professional antivirus or enterprise security solutions.

## Author

**Vinuba K**

MSc Integrated – Theoretical Computer Science
PSG College of Technology
