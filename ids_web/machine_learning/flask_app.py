from flask import Flask, jsonify
import pandas as pd
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# ✅ Load cleaned dataset (path is relative to the project structure)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
df = pd.read_csv(os.path.join(BASE_DIR, "ids_app", "cleaned_dataset.csv"))

@app.route('/get_data')
def get_cleaned_data():
    try:
        attack_summary = df["Label"].value_counts().to_dict()  
        return jsonify(attack_summary)
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
