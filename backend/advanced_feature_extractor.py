import os
import re
from typing import Dict
try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False
    print("PyPDF2 not available, using binary analysis")

try:
    import pdfplumber
    PDFPLUMBER_AVAILABLE = True
except ImportError:
    PDFPLUMBER_AVAILABLE = False
    print("pdfplumber not available, using basic analysis")

def extract_features_advanced(pdf_path: str) -> Dict[str, float]:
    """
    Advanced PDF feature extraction using proper PDF libraries.
    """
    try:
        features = {}
        
        # Basic file info
        features['pdfsize'] = os.path.getsize(pdf_path) / 1024.0  # KB
        
        if PYPDF2_AVAILABLE:
            features.update(_extract_pypdf2_features(pdf_path))
        
        if PDFPLUMBER_AVAILABLE:
            features.update(_extract_pdfplumber_features(pdf_path))
        
        # Fallback to binary analysis
        features.update(_extract_binary_features(pdf_path))
        
        return features
    except Exception as e:
        print(f"Error in advanced extraction: {e}")
        return _extract_binary_features(pdf_path)

def _extract_pypdf2_features(pdf_path: str) -> Dict[str, float]:
    """Extract features using PyPDF2."""
    features = {}
    
    try:
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            
            # Basic structure
            features['pages'] = len(pdf_reader.pages)
            features['pageno'] = features['pages']
            
            # Check for encryption
            features['encrypt'] = 1 if pdf_reader.is_encrypted else 0
            features['isEncrypted'] = features['encrypt']
            
            # Extract metadata
            if pdf_reader.metadata:
                metadata = pdf_reader.metadata
                features['title characters'] = len(metadata.get('/Title', '')) if metadata.get('/Title') else 0
                features['metadata size'] = len(str(metadata)) * 0.1  # heuristic
            else:
                features['title characters'] = 0
                features['metadata size'] = 0
            
            # Check for JavaScript and actions
            js_count = 0
            aa_count = 0
            launch_count = 0
            
            for page in pdf_reader.pages:
                if '/JS' in str(page):
                    js_count += 1
                if '/AA' in str(page):
                    aa_count += 1
                if '/Launch' in str(page):
                    launch_count += 1
            
            features['JS'] = js_count
            features['Javascript'] = js_count
            features['AA'] = aa_count
            features['launch'] = launch_count
            
    except Exception as e:
        print(f"PyPDF2 extraction error: {e}")
        # Return defaults
        return {
            'pages': 0, 'pageno': 0, 'encrypt': 0, 'isEncrypted': 0,
            'title characters': 0, 'metadata size': 0,
            'JS': 0, 'Javascript': 0, 'AA': 0, 'launch': 0
        }
    
    return features

def _extract_pdfplumber_features(pdf_path: str) -> Dict[str, float]:
    """Extract features using pdfplumber."""
    features = {}
    
    try:
        import pdfplumber
        with pdfplumber.open(pdf_path) as pdf:
            # Text analysis
            total_text = ""
            for page in pdf.pages:
                if page.extract_text():
                    total_text += page.extract_text() + " "
            
            features['text'] = 1 if len(total_text.strip()) > 100 else 0
            
            # Count images
            image_count = 0
            for page in pdf.pages:
                if page.images:
                    image_count += len(page.images)
            features['images'] = image_count
            
            # Check for forms and annotations
            form_count = 0
            for page in pdf.pages:
                if hasattr(page, 'chars') and page.chars:
                    # Simple heuristic for form fields
                    if len(page.chars) > 0:
                        form_count += 1
            
            features['Acroform'] = min(form_count, 10)  # Cap at 10
            
    except Exception as e:
        print(f"pdfplumber extraction error: {e}")
        return {'text': 0, 'images': 0, 'Acroform': 0}
    
    return features

def _extract_binary_features(pdf_path: str) -> Dict[str, float]:
    """Fallback binary analysis."""
    features = {}
    
    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
        
        # PDF structure keywords
        features['obj'] = len(re.findall(b'obj', content))
        features['endobj'] = len(re.findall(b'endobj', content))
        features['stream'] = len(re.findall(b'stream', content))
        features['endstream'] = len(re.findall(b'endstream', content))
        features['xref'] = len(re.findall(b'xref', content))
        features['trailer'] = len(re.findall(b'trailer', content))
        features['startxref'] = len(re.findall(b'startxref', content))
        
        # Security-related keywords
        features['OpenAction'] = len(re.findall(b'/OpenAction', content))
        features['EmbeddedFile'] = len(re.findall(b'/EmbeddedFile', content))
        features['embedded files'] = features['EmbeddedFile']
        features['ObjStm'] = len(re.findall(b'/ObjStm', content))
        features['XFA'] = len(re.findall(b'/XFA', content))
        features['RichMedia'] = len(re.findall(b'/RichMedia', content))
        features['JBIG2Decode'] = len(re.findall(b'/JBIG2Decode', content))
        features['Colors'] = len(re.findall(b'/ColorSpace', content)) + len(re.findall(b'/DeviceRGB', content))
        
        # Additional features
        features['xref Length'] = features['xref'] * 10
        features['len'] = len(content)
        features['extend'] = len(re.findall(b'extend', content.lower()))
        
    except Exception as e:
        print(f"Binary extraction error: {e}")
        # Return all zeros if everything fails
        return {
            'obj': 0, 'endobj': 0, 'stream': 0, 'endstream': 0,
            'xref': 0, 'trailer': 0, 'startxref': 0, 'OpenAction': 0,
            'EmbeddedFile': 0, 'embedded files': 0, 'ObjStm': 0,
            'XFA': 0, 'RichMedia': 0, 'JBIG2Decode': 0, 'Colors': 0,
            'xref Length': 0, 'len': 0, 'extend': 0
        }
    
    return features

def get_all_features_vector(pdf_path: str, all_feature_names: list) -> list:
    """Get feature vector matching the expected feature names."""
    features = extract_features_advanced(pdf_path)
    vector = [float(features.get(f, 0)) for f in all_feature_names]
    return vector
