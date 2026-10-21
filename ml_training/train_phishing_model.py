"""
CyberShield Phishing Detection System
Machine Learning Model Training & Comparative Evaluation Script

This script trains, benchmarks, and evaluates four supervised machine learning
algorithms on the phishing detection corpus:
1. Multinomial Naive Bayes (MNB)
2. Logistic Regression (LR)
3. Random Forest Classifier (RF)
4. Support Vector Classifier (Linear SVC)

Metrics calculated:
- Accuracy
- Precision
- Recall
- F1-Score
- 2x2 Confusion Matrix
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

def train_and_evaluate():
    print("=" * 70)
    print("  CYBERSHIELD AI-ML PHISHING CLASSIFICATION ENGINE TRAINING")
    print("=" * 70)

    # 1. Load Email Dataset
    dataset_path = os.path.join(os.path.dirname(__file__), "dataset", "phishing_emails_dataset.csv")
    if not os.path.exists(dataset_path):
        print(f"[!] Dataset not found at: {dataset_path}")
        return

    df = pd.read_csv(dataset_path)
    print(f"\n[+] Loaded Dataset: {len(df)} total samples.")
    print(f"    - Phishing Samples (Class 1): {sum(df['label'] == 1)}")
    print(f"    - Legitimate Samples (Class 0): {sum(df['label'] == 0)}")

    X = df['text']
    y = df['label']

    # 2. Train / Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    print(f"[+] Dataset split: {len(X_train)} training samples, {len(X_test)} evaluation samples.")

    # 3. TF-IDF Feature Extraction
    tfidf = TfidfVectorizer(ngram_range=(1, 2), max_features=1000, stop_words='english')
    X_train_vec = tfidf.fit_transform(X_train)
    X_test_vec = tfidf.transform(X_test)
    print(f"[+] Extracted {X_train_vec.shape[1]} TF-IDF feature tokens.")

    # 4. Model Training & Comparison
    models = {
        "Multinomial Naive Bayes": MultinomialNB(),
        "Logistic Regression": LogisticRegression(random_state=42),
        "Random Forest Classifier": RandomForestClassifier(n_estimators=100, random_state=42),
        "Linear Support Vector Machine": LinearSVC(random_state=42)
    }

    results = []

    print("\n" + "=" * 70)
    print(f"{'Algorithm':<32} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 70)

    best_model_name = ""
    best_f1 = -1.0
    best_model = None

    for name, model in models.items():
        model.fit(X_train_vec, y_train)
        y_pred = model.predict(X_test_vec)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        results.append({
            "model": name,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "confusion_matrix": cm.tolist()
        })

        print(f"{name:<32} | {acc * 100:>8.2f}% | {prec * 100:>8.2f}% | {rec * 100:>8.2f}% | {f1 * 100:>8.2f}%")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = model

    print("=" * 70)
    print(f"\n[★] Selected Production Model: {best_model_name} (F1-Score: {best_f1 * 100:.2f}%)")

    # 5. Confusion Matrix Breakdown for Selected Model
    best_cm = confusion_matrix(y_test, best_model.predict(X_test_vec))
    tn, fp, fn, tp = best_cm.ravel()
    print("\n[+] Confusion Matrix for Final Project Defense:")
    print(f"    - True Negatives (Legitimate correctly identified): {tn}")
    print(f"    - False Positives (Legitimate falsely flagged as Phishing): {fp}")
    print(f"    - False Negatives (Phishing missed): {fn}")
    print(f"    - True Positives (Phishing correctly caught): {tp}")

    # 6. Top Extracted Phishing Keywords by Weight
    feature_names = tfidf.get_feature_names_out()
    if hasattr(best_model, "feature_importances_"):
        top_indices = np.argsort(best_model.feature_importances_)[::-1][:10]
        print("\n[+] Top 10 Influential ML Feature Tokens:")
        for idx in top_indices:
            print(f"    • {feature_names[idx]:<20} (Weight: {best_model.feature_importances_[idx]:.4f})")

    # 7. Export metadata to JSON
    metadata = {
        "production_model": best_model_name,
        "evaluation_summary": results,
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)}
    }
    output_path = os.path.join(os.path.dirname(__file__), "model_evaluation_metrics.json")
    with open(output_path, "w") as f:
        json.dump(metadata, f, indent=4)
    print(f"\n[✔] Evaluation metrics saved to: {output_path}")

if __name__ == "__main__":
    train_and_evaluate()
