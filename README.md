# Port-Scanner
Developed a machine learning-based system that combines network scanning with AI to predict device vulnerabilities. Implemented risk classification and explanation features to improve security monitoring for IoT and industrial networks.


# Project Structure
```
Port-Scanner
│
├── scanner.py # Main Python script
├── models/
│ ├── inverter_rf.joblib # Trained Random Forest model
│ └── feature_columns.joblib # Feature columns used by the model
└── README.md # This file
```

 **Important:** Place the `inverter_rf.joblib` and `feature_columns.joblib` files in the `ML_PArt` folder, and update paths in `predict_device.py` if necessary.

# Prerequisites

1. **Python 3.13** or higher installed.  
2. **nmap** installed and added to system PATH:

   ### Windows:
   - Download Nmap from [https://nmap.org/download.html#windows](https://nmap.org/download.html#windows)  
   - Install it and ensure `nmap.exe` is in your PATH (e.g., `C:\Program Files (x86)\Nmap\`).  
   - Test with:
     ```bash
     nmap --version
     ```

3. **Python modules**: Install required packages via pip:
```terminal
pip install pandas joblib python-nmap scikit-learn
```
# Output

Scanned device: 127.0.0.1
open_ports:  ['3306 - MySQL', '27017 - MongoDB']
Vendor: Generic, Max CVSS: 9.0
Prediction: SAFE (prob=0.430)
Reasons: 2 high-risk ports open; max CVSS ≥ 8.0
