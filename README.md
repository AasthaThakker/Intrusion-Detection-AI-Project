# Log Analyzer – Intrusion Detection

A lightweight web-based tool that accepts any kind of log file (CSV, text-formatted logs, exported Windows logs, network traces, etc.) and performs:

Automatic preprocessing

* K-Nearest Neighbour intrusion classification
* Interactive 3D topology view showing threat spread and severity

This project is ideal for cybersecurity students, SOC analysts, and demo environments where logs come in mixed formats.

# Key Capabilities
## 1. Log Handling
* Works even if column names differ
* Auto-detects numerical vs categorical fields
* Drops timestamps/IPs/IDs automatically
* Pads or trims features to match model input

## 2. Intrusion Identification
* KNeighborsClassifier used for prediction
* Results categorized as Normal or Intrusion
* Threat levels assigned dynamically

## 3. 3D Visualization
* Nodes represent individual log entries
Red = intrusion, Green = normal

# Getting Started
## 1. Install dependencies
pip install -r requirements.txt

## 2. Ensure the model file exists
kneighbors_model.pkl

## 3. Run the Flask app
python app.py

## 4. Open in browser
http://localhost:5000

# 📂 File Structure
├─ app.py                # Flask backend + prediction + explanations
├─ templates/
│   └─ index.html        # UI layout
├─ static/
│   ├─ script.js         # AJAX + rendering + 3D graph
│   └─ style.css         # UI styling
├─ kneighbors_model.pkl  # Trained model
├─ README.md             # Project overview
Node size reflects severity score

Animated topology orbit

# Supported Inputs
1. Windows event exports
2. Firewall logs
3. Proxy logs
4. Web server logs
5. Router/security gateway dumps
6. CSV with mixed data types

No strict schema required.

# ⚠️ Notes
* Predictions depend on how the original model was trained
* Explanations improve clarity but are not forensic evidence
* Padding missing features allows universal compatibility, but accuracy varies
