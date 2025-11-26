from flask import Flask, render_template, request, jsonify
import pickle
import pandas as pd
import numpy as np
from io import StringIO
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import os

app = Flask(__name__)

# Load the saved model
MODEL_PATH = 'kneighbors_model.pkl'

# Load model
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

# Initialize encoders and scalers
label_encoders = {}
scaler = MinMaxScaler()

def analyze_row(row):
    """Generate human-readable reasons why a log line might be suspicious."""
    reasons = []
    
    SENSITIVE_PORTS = {21, 22, 23, 25, 53, 110, 143, 445, 3389, 3306, 1433, 5900, 8080, 8443}
    SUSPICIOUS_PROTOCOLS = ['telnet', 'ftp', 'rdp', 'smb', 'vnc', 'ssh']
    ERROR_KEYWORDS = ['fail', 'denied', 'unauthorized', 'forbidden', 'error', 'timeout']
    ATTACK_KEYWORDS = ['sql', 'injection', 'xss', 'overflow', 'exploit', 'malware', 'brute', 'scan']
    AUTH_KEYWORDS = ['login', 'auth', 'credential', 'password']
    
    for col, val in row.items():
        if pd.isna(val):
            continue
        
        col_lower = str(col).lower()
        text = str(val)
        lower = text.lower()

        # Protocol / service hints
        if any(p in lower for p in SUSPICIOUS_PROTOCOLS):
            reasons.append(f"Protocol/service in '{col}' looks sensitive: '{text}'")

        # Ports
        if 'port' in col_lower:
            try:
                port = int(str(val).split('/')[0])
                if port in SENSITIVE_PORTS:
                    reasons.append(f"Port {port} in '{col}' is commonly targeted in attacks")
                elif port > 1024:
                    reasons.append(f"High, non-standard port {port} in '{col}'")
            except ValueError:
                pass

        # Status / result fields
        if any(k in col_lower for k in ['status', 'result', 'response', 'code']):
            if not any(ok in lower for ok in ['200', 'ok', 'success', 'allowed']):
                reasons.append(f"Non-success status in '{col}': '{text}'")

        # User / account hints
        if any(k in col_lower for k in ['user', 'account', 'login']):
            if any(admin in lower for admin in ['admin', 'root', 'system']):
                reasons.append(f"Privileged account seen in '{col}': '{text}'")

        # Error / attack wording
        if any(k in lower for k in ERROR_KEYWORDS):
            reasons.append(f"Error/denied wording in '{col}': '{text}'")
        if any(k in lower for k in ATTACK_KEYWORDS):
            reasons.append(f"Possible attack keyword in '{col}': '{text}'")
        if any(k in lower for k in AUTH_KEYWORDS) and any(k in lower for k in ERROR_KEYWORDS):
            reasons.append(f"Failed authentication activity in '{col}': '{text}'")

        # Size / length anomalies (if numeric-ish)
        if any(k in col_lower for k in ['size', 'bytes', 'length']):
            try:
                size_val = float(text)
                if size_val > 10_000:
                    reasons.append(f"Unusually large payload/size ({size_val}) in '{col}'")
            except ValueError:
                pass

    # Deduplicate to keep it readable
    unique_reasons = list(dict.fromkeys(reasons))
    return unique_reasons


def preprocess_data(df):
    """Preprocess the input dataframe - auto-detect and handle all column types"""

    # Print columns for debugging
    print("Columns found:", df.columns.tolist())
    print("First row:", df.iloc[0].tolist() if len(df) > 0 else "Empty dataframe")
    
    # Common columns to drop (IPs, timestamps, identifiers)
    drop_patterns = ['ip', 'timestamp', 'time', 'date', 'id', 'index']
    cols_to_drop = []
    
    for col in df.columns:
        col_lower = col.lower()
        if any(pattern in col_lower for pattern in drop_patterns):
            cols_to_drop.append(col)
    
    # Drop identified columns
    if cols_to_drop:
        print(f"Dropping columns: {cols_to_drop}")
        df = df.drop(columns=cols_to_drop)
    
    # Separate numerical and categorical columns
    numerical_cols = []
    categorical_cols = []
    
    for col in df.columns:
        # Try to convert to numeric
        try:
            pd.to_numeric(df[col], errors='raise')
            numerical_cols.append(col)
        except:
            categorical_cols.append(col)
    
    print(f"Numerical columns: {numerical_cols}")
    print(f"Categorical columns: {categorical_cols}")
    
    # Encode categorical features
    for feature in categorical_cols:
        if feature not in label_encoders:
            label_encoders[feature] = LabelEncoder()
            label_encoders[feature].fit(df[feature].astype(str))
        
        try:
            df[feature] = label_encoders[feature].transform(df[feature].astype(str))
        except ValueError:
            # If unknown categories exist, fit again
            label_encoders[feature].fit(df[feature].astype(str))
            df[feature] = label_encoders[feature].transform(df[feature].astype(str))
    
    # Scale numerical features
    if numerical_cols:
        try:
            df[numerical_cols] = scaler.transform(df[numerical_cols])
        except:
            # First time - fit and transform
            df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

    # ---- FEATURE ALIGNMENT WITH MODEL ----
    # Stable column order
    df = df.reindex(sorted(df.columns), axis=1)

    if hasattr(model, 'n_features_in_'):
        expected = model.n_features_in_
        current = df.shape[1]
        print(f"Model expects {expected} features, current data has {current}")

        if current > expected:
            # Too many columns → keep first N
            print(f"Truncating features from {current} to {expected}")
            df = df.iloc[:, :expected]

        elif current < expected:
            # Too few columns → pad with zeros
            missing = expected - current
            print(f"Padding from {current} to {expected} features with {missing} zero columns")

            for i in range(missing):
                df[f'_pad_{i}'] = 0

            # Reorder again so we keep exactly expected features
            df = df.reindex(sorted(df.columns), axis=1)
            df = df.iloc[:, :expected]

    return df



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Check if file upload or text input
        if 'file' in request.files and request.files['file'].filename != '':
            file = request.files['file']
            # Try to detect delimiter (comma or tab)
            try:
                df = pd.read_csv(file, sep=',')
                if len(df.columns) == 1:  # If only one column, might be tab-separated
                    file.seek(0)
                    df = pd.read_csv(file, sep='\t')
            except:
                file.seek(0)
                df = pd.read_csv(file, sep='\t')
        elif 'data' in request.form and request.form['data'].strip() != '':
            csv_data = request.form['data']
            # Try comma first, then tab
            try:
                df = pd.read_csv(StringIO(csv_data), sep=',')
                if len(df.columns) == 1:  # If only one column, might be tab-separated
                    df = pd.read_csv(StringIO(csv_data), sep='\t')
            except:
                df = pd.read_csv(StringIO(csv_data), sep='\t')
        else:
            return jsonify({'error': 'No data provided'}), 400
        
        # Print dataframe info for debugging
        print(f"\nDataframe shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")
        print(f"First few rows:\n{df.head()}")
        
        # Store original data for response
        original_count = len(df)

        # Row-level explanation (before preprocessing drops IPs/timestamps)
        row_explanations = []
        for _, row in df.iterrows():
            row_explanations.append(analyze_row(row))
        
        # Preprocess data
        processed_df = preprocess_data(df.copy())
        
        print(f"\nProcessed dataframe shape: {processed_df.shape}")
        print(f"Processed columns: {processed_df.columns.tolist()}")
        print(f"Processed data sample:\n{processed_df.head()}")
        
        # Make predictions
        predictions = model.predict(processed_df)
        
        # Calculate statistics
        intrusion_count = int(np.sum(predictions == 1))
        normal_count = int(np.sum(predictions == 0))
        intrusion_percentage = (intrusion_count / original_count) * 100
        normal_percentage = (normal_count / original_count) * 100
        
        # Prepare detailed results
        results = []
        for idx, pred in enumerate(predictions):
            results.append({
                'index': idx + 1,
                'prediction': 'Intrusion' if pred == 1 else 'Normal',
                'threat_level': 'High' if pred == 1 else 'Low'
            })
        
        return jsonify({
            'success': True,
            'total_records': original_count,
            'intrusion_count': intrusion_count,
            'normal_count': normal_count,
            'intrusion_percentage': round(intrusion_percentage, 2),
            'normal_percentage': round(normal_percentage, 2),
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)