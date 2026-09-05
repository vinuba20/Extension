import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from sklearn.feature_selection import RFE
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
import pickle
import os

# Load data
df = pd.read_csv('PDFMalware2022.csv')

# Drop 'File name' as it's an identifier
df = df.drop(['File name'], axis=1)

# Map 'Class' to 0/1
# Handling it before dropping NaNs in case 'Class' has NaNs or non-standard values
df['Class'] = df['Class'].map({'Malicious': 1, 'Benign': 0})

# Handle categorical 'text'
if 'text' in df.columns:
    df['text'] = df['text'].map({'No': 0, 'Yes': 1})

# Drop 'header' as it's categorical and usually messy
if 'header' in df.columns:
    df = df.drop(['header'], axis=1)

# Force all other columns to numeric, coercing errors to NaN
# This handles the '(most', 'pdfid.py' etc. strings found in numeric columns
for col in df.columns:
    if col != 'Class':
        df[col] = pd.to_numeric(df[col], errors='coerce')

# Drop rows with NaNs (original NaNs + coerced NaNs)
df = df.dropna()

print(f"Data shape after cleaning: {df.shape}")

# Split into X and y
X = df.drop('Class', axis=1)
y = df['Class']

# Oversampling with SMOTE
smote = SMOTE(random_state=0)
os_X, os_y = smote.fit_resample(X, y)
os_X = pd.DataFrame(data=os_X, columns=X.columns)
os_y = pd.DataFrame(data=os_y, columns=['Class'])

# Scaling
scaler = StandardScaler().fit(os_X)
os_X_scaled = pd.DataFrame(scaler.transform(os_X), columns=os_X.columns)

# Feature Selection with RFE
estimator = SVC(kernel="linear")
rfe = RFE(estimator, n_features_to_select=20)
rfe = rfe.fit(os_X_scaled, os_y.values.ravel())
cols_to_keep = rfe.support_
cols = np.array(os_X.columns)[np.array(cols_to_keep)]

X_final = os_X_scaled[cols]
y_final = os_y['Class']

# Training the final model with best params from notebook
# Best params: {'C': 10, 'gamma': 'auto', 'kernel': 'rbf'}
X_train, X_test, y_train, y_test = train_test_split(X_final, y_final, test_size=0.25, random_state=0, shuffle=True)
svm = SVC(C=10, kernel="rbf", gamma='auto', probability=True)
svm.fit(X_train, y_train)

# Create a final scaler specifically for the selected features
# We fit it on the original (unscaled) os_X but only the selected columns
final_scaler = StandardScaler().fit(os_X[cols])

print(f"Training Data Accuracy: {svm.score(X_train, y_train)}")
print(f"Test Data Accuracy: {svm.score(X_test, y_test)}")

# Save the model, the scaler, and the selected features in both root and backend directories
model_data = {
    'model': svm,
    'scaler': final_scaler,
    'selected_features': cols
}

os.makedirs('backend', exist_ok=True)
backend_model_path = os.path.join('backend', 'pdf_malware_model.pkl')
with open(backend_model_path, 'wb') as f:
    pickle.dump(model_data, f)
print(f"Model saved to {backend_model_path}")

with open('pdf_malware_model.pkl', 'wb') as f:
    pickle.dump(model_data, f)
print("Model saved to pdf_malware_model.pkl")
