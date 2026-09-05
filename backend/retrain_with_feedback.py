"""
Retrain the PDF malware detection model with user feedback
This script uses feedback from user decisions to improve model accuracy
"""

import os
import json
import requests
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FEEDBACK_FILE = "feedback_data.jsonl"
MODEL_PATH = "pdf_rf_model.pkl"

def load_feedback_data():
    """Load feedback data from JSONL file"""
    if not os.path.exists(FEEDBACK_FILE):
        logger.warning(f"No feedback file found: {FEEDBACK_FILE}")
        return []
    
    feedback_data = []
    with open(FEEDBACK_FILE, 'r') as f:
        for line in f:
            try:
                feedback_data.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    
    logger.info(f"Loaded {len(feedback_data)} feedback entries")
    return feedback_data

def download_and_extract_features(url, label):
    """Download PDF from URL and extract features"""
    try:
        logger.info(f"Downloading: {url}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, stream=True, timeout=15, headers=headers)
        response.raise_for_status()
        
        # Save to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            for chunk in response.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name
        
        # Extract features
        from advanced_feature_extractor import get_all_features_vector
        from summarizer import get_feature_names
        
        feature_names = get_feature_names()
        features = get_all_features_vector(tmp_path, feature_names)
        
        # Clean up
        os.remove(tmp_path)
        
        return features, label
        
    except Exception as e:
        logger.error(f"Failed to process {url}: {e}")
        return None, None

def retrain_model():
    """Main retraining function"""
    logger.info("🔄 Starting model retraining with feedback...")
    
    # Load feedback
    feedback_data = load_feedback_data()
    if len(feedback_data) < 10:
        logger.warning(f"Not enough feedback samples ({len(feedback_data)}). Need at least 10.")
        return
    
    # Load existing model
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Model file not found: {MODEL_PATH}")
        return
    
    try:
        loaded_data = joblib.load(MODEL_PATH)
        if isinstance(loaded_data, dict):
            model = loaded_data['model']
            scaler = loaded_data.get('scaler')
            feature_names = list(loaded_data.get('selected_features', []))
        else:
            model = loaded_data
            scaler = None
            feature_names = list(model.feature_names_in_)
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return
    
    logger.info(f"Loaded existing model with {len(feature_names)} features")
    
    # Process feedback data
    X_new = []
    y_new = []
    
    for feedback in feedback_data:
        url = feedback['url']
        actual_label = feedback['actual_label']
        
        # Convert label to numeric
        label_numeric = 1 if actual_label == 'malicious' else 0
        
        # Download and extract features
        features, label = download_and_extract_features(url, label_numeric)
        if features is not None:
            X_new.append(features)
            y_new.append(label)
    
    if len(X_new) == 0:
        logger.warning("No valid features extracted from feedback data")
        return
    
    logger.info(f"Successfully extracted features for {len(X_new)} samples")
    
    # Convert to arrays
    X_new = np.array(X_new)
    y_new = np.array(y_new)
    
    # Load original training data (if available)
    # For now, we'll just add the new data to the model
    # In production, you'd want to load the original dataset
    
    # Retrain model with new data
    logger.info("Retraining model...")
    
    # If we have a scaler, fit it on new data
    if scaler is not None:
        scaler.partial_fit(X_new)
        X_new_scaled = scaler.transform(X_new)
    else:
        X_new_scaled = X_new
    
    # Update model (warm start)
    model.fit(X_new_scaled, y_new)
    
    # Save updated model
    save_data = {
        'model': model,
        'scaler': scaler,
        'selected_features': feature_names
    }
    
    # Backup old model
    backup_path = MODEL_PATH + ".backup"
    if os.path.exists(MODEL_PATH):
        os.rename(MODEL_PATH, backup_path)
        logger.info(f"Backed up old model to {backup_path}")
    
    # Save new model
    joblib.dump(save_data, MODEL_PATH)
    logger.info(f"✅ Retrained model saved to {MODEL_PATH}")
    
    # Clear feedback file
    os.remove(FEEDBACK_FILE)
    logger.info("✅ Feedback file cleared after retraining")
    
    logger.info("🎉 Retraining complete!")

if __name__ == "__main__":
    retrain_model()
