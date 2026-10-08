import os
import csv
import joblib
from typing import Tuple, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

MODEL_FILE = os.path.join(os.path.dirname(__file__), "csic_model.joblib")
DATASET_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sample_logs", "csic_database.csv")

class CSICAnomalyClassifier:
    def __init__(self):
        self.pipeline: Optional[Pipeline] = None
        self.is_loaded: bool = False
        self.load_or_train()

    def train_on_csic_dataset(self, csv_path: str = DATASET_FILE):
        print(f"Loading CSIC 2010 HTTP Dataset from: {csv_path}...")
        texts = []
        labels = []

        if not os.path.exists(csv_path):
            print(f"Dataset file not found at {csv_path}. Using fallback synthetic dataset.")
            self._train_fallback()
            return

        with open(csv_path, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader)
            
            # Identify column indices
            # Header: ['', 'Method', 'User-Agent', ..., 'content', 'classification', 'URL']
            url_idx = 16 if len(header) > 16 else -1
            content_idx = 14 if len(header) > 14 else -1
            method_idx = 1 if len(header) > 1 else -1
            class_idx = 15 if len(header) > 15 else -1

            for row in reader:
                if len(row) > 15:
                    method = row[method_idx] if method_idx != -1 else "GET"
                    url = row[url_idx] if url_idx != -1 else ""
                    content = row[content_idx] if content_idx != -1 else ""
                    label_str = row[class_idx]
                    
                    # Target label: 1 = Anomalous, 0 = Normal
                    label = 1 if label_str == "1" or row[0].lower() == "anomalous" else 0
                    
                    # Combine Method, URL, and Content payload into single text feature
                    text_feature = f"{method} {url} {content}".strip()
                    texts.append(text_feature)
                    labels.append(label)

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
        print(f"CSIC 2010 Model Training Complete! Validation Accuracy: {acc * 100:.2f}%")

        # Save model pipeline
        joblib.dump(self.pipeline, MODEL_FILE)
        print(f"Model saved to: {MODEL_FILE}")
        self.is_loaded = True

    def _train_fallback(self):
        # Quick fallback training if CSIC CSV is not present
        sample_texts = [
            "GET /home", "GET /products", "GET /about", "POST /login",
            "GET /.env", "GET /wp-config.php", "GET /products?id=1 UNION SELECT null, username, password FROM users--",
            "POST /admin/login", "GET /etc/passwd", "GET /search?q=%27%20UNION%20SELECT%20CHAR(39)"
        ]
        sample_labels = [0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(2, 4), analyzer='char_wb')),
            ('clf', LogisticRegression())
        ])
        self.pipeline.fit(sample_texts, sample_labels)
        joblib.dump(self.pipeline, MODEL_FILE)
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

        text = f"{method} {endpoint} {raw_log}".strip()
        try:
            probs = self.pipeline.predict_proba([text])[0]
            # probs[1] is probability of class 1 (Anomalous)
            anomaly_prob = float(probs[1])
            is_anomaly = anomaly_prob > 0.5
            return is_anomaly, round(anomaly_prob, 3)
        except Exception as e:
            print(f"Prediction error: {e}")
            return False, 0.0

# Singleton classifier instance
ml_classifier = CSICAnomalyClassifier()
