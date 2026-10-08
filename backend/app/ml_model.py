import os
import csv
import re
import joblib
from urllib.parse import unquote, urlparse
from typing import Tuple, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

MODEL_FILE = os.path.join(os.path.dirname(__file__), "csic_model.joblib")
DATASET_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sample_logs", "csic_database.csv")

def clean_request(url: str, body: str = "") -> str:
    """
    Shared clean_request function used by both training and inference.
    URL-decodes, strips scheme/host and HTTP/1.x suffix, and removes the URL path,
    keeping only the query string and body.
    """
    url = url or ""
    body = body or ""

    # Strip HTTP/1.x or HTTP/2 suffix
    url = re.sub(r"\s+HTTP/\d\.\d$", "", url, flags=re.IGNORECASE)

    # URL-decode
    decoded_url = unquote(url)
    decoded_body = unquote(body)

    # Parse query string and body, stripping scheme/host and URL path
    parsed = urlparse(decoded_url)
    query_str = parsed.query if parsed.query else ""
    if not query_str and "?" in decoded_url:
        query_str = decoded_url.split("?", 1)[1]

    parts = []
    if query_str.strip():
        parts.append(query_str.strip())
    if decoded_body.strip():
        parts.append(decoded_body.strip())

    return " ".join(parts).strip()

class CSICAnomalyClassifier:
    def __init__(self):
        self.pipeline: Optional[Pipeline] = None
        self.is_loaded: bool = False
        self.load_or_train()

    def train_on_csic_dataset(self, csv_path: str = DATASET_FILE):
        print(f"Loading CSIC 2010 HTTP Dataset from: {csv_path}...")
        texts = []
        labels = []

        if os.path.exists(csv_path):
            with open(csv_path, mode="r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                header = next(reader)

                url_idx = 16 if len(header) > 16 else -1
                content_idx = 14 if len(header) > 14 else -1
                class_idx = 15 if len(header) > 15 else -1

                for row in reader:
                    if len(row) > 15:
                        url = row[url_idx] if url_idx != -1 else ""
                        content = row[content_idx] if content_idx != -1 else ""
                        label_str = row[class_idx]
                        
                        label = 1 if label_str == "1" or row[0].lower() == "anomalous" else 0
                        cleaned_text = clean_request(url, content)
                        
                        texts.append(cleaned_text)
                        labels.append(label)

        # Add 800 synthetic normal requests in demo logs style
        demo_normal_requests = [
            "/home", "/products", "/products?id=1", "/products?id=2", "/products?id=3", "/products?id=4", "/products?id=5",
            "/products?category=shoes", "/products?category=electronics", "/products?category=apparel",
            "/about", "/contact", "/blog/post-1", "/blog/post-2", "/search?q=shoes", "/search?q=laptop", "/search?q=phone",
            "/api/v1/items?page=1&limit=10", "/profile?user=john", "/settings?lang=en"
        ]
        print("Adding 800 synthetic normal requests in demo logs style...")
        for i in range(800):
            req_url = demo_normal_requests[i % len(demo_normal_requests)]
            cleaned = clean_request(req_url, "")
            texts.append(cleaned)
            labels.append(0)

        print(f"Extracted {len(texts)} samples ({labels.count(0)} Normal, {labels.count(1)} Anomalous).")

        # Split Train/Test
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )

        # Build Character N-Gram TF-IDF + Logistic Regression Pipeline
        print("Training CSIC ML Anomaly Detection Model (TF-IDF + Logistic Regression)...")
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(2, 4), max_features=15000, analyzer='char_wb')),
            ('clf', LogisticRegression(C=5.0, max_iter=500, solver='liblinear'))
        ])

        self.pipeline.fit(X_train, y_train)

        # Evaluate model accuracy
        y_pred = self.pipeline.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"CSIC Model Retrained with clean_request! Validation Accuracy: {acc * 100:.2f}%")

        # Save model pipeline
        joblib.dump(self.pipeline, MODEL_FILE)
        print(f"Model saved to: {MODEL_FILE}")
        self.is_loaded = True

    def load_or_train(self):
        if os.path.exists(MODEL_FILE):
            try:
                self.pipeline = joblib.load(MODEL_FILE)
                self.is_loaded = True
                print(f"Loaded CSIC ML Anomaly Model from {MODEL_FILE}")
                return
            except Exception as e:
                print(f"Failed to load {MODEL_FILE}: {e}")

        self.train_on_csic_dataset()

    def predict_anomaly(self, method: str, endpoint: str, raw_log: str = "") -> Tuple[bool, float]:
        if not self.is_loaded or self.pipeline is None:
            return False, 0.0

        cleaned_text = clean_request(endpoint, raw_log if "?" not in endpoint and "=" not in endpoint else "")
        try:
            probs = self.pipeline.predict_proba([cleaned_text])[0]
            anomaly_prob = float(probs[1])
            is_anomaly = anomaly_prob > 0.5
            return is_anomaly, round(anomaly_prob, 3)
        except Exception as e:
            print(f"Prediction error: {e}")
            return False, 0.0

# Singleton classifier instance
ml_classifier = CSICAnomalyClassifier()
