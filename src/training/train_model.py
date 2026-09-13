import json
import joblib
import sys
import pandas as pd
import numpy as np
import scipy.sparse as sp
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

file_path = Path(__file__).resolve()
project_root = file_path.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.config import (
        FEATURES_CSV, MODELS_DIR, REPORTS_DIR,
        MODEL_FILE, VEC_FILE, COLS_FILE,
        CLASSIFICATION_REPORT_FILE, METRICS_JSON_FILE,
        CONFUSION_MATRIX_FILE, FEATURE_IMPORTANCE_CSV, FEATURE_IMPORTANCE_PNG
    )
except ImportError:
    from config import (
        FEATURES_CSV, MODELS_DIR, REPORTS_DIR,
        MODEL_FILE, VEC_FILE, COLS_FILE,
        CLASSIFICATION_REPORT_FILE, METRICS_JSON_FILE,
        CONFUSION_MATRIX_FILE, FEATURE_IMPORTANCE_CSV, FEATURE_IMPORTANCE_PNG
    )

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import GroupShuffleSplit, GroupKFold, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score
)

# Columns to strictly EXCLUDE from numeric ML features for Pre-Execution Threat Detection & Data Leakage Prevention
EXCLUDE_COLS = [
    "ip", "timestamp", "method", "url", "path", "query", "decoded_query",
    "body", "decoded_body", "content_type",
    "text", "label", "attack_type", "label_source", "request_hash",
    # Response-time / Post-incident features (Cannot know before server processes):
    "status_code", "is_error_response", "response_size", "response_time",
    # Static Lab IP Context Stats (prevents distribution shift during real-time inference):
    "ip_request_count", "ip_unique_path_count", "ip_unique_query_count"
]

def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if not FEATURES_CSV.exists():
        print(f"ERROR: File {FEATURES_CSV} does not exist. Run feature_extractor.py first!")
        return

    df = pd.read_csv(FEATURES_CSV).fillna("")
    total_samples = len(df)

    normal_count = (df["label"] == 0).sum()
    sqli_count = (df["label"] == 1).sum()

    print("====================================")
    print("DATASET SUMMARY BEFORE TRAIN SPLIT")
    print("====================================")
    print(f"Total requests: {total_samples}")
    print(f"Normal samples (0): {normal_count} ({normal_count/total_samples*100:.2f}%)")
    print(f"SQLi samples (1): {sqli_count} ({sqli_count/total_samples*100:.2f}%)")
    print(f"Unique request hashes: {df['request_hash'].nunique()}")
    print("====================================")

    # Determine numeric feature columns
    numeric_cols = [col for col in df.columns if col not in EXCLUDE_COLS]
    print(f"Using {len(numeric_cols)} numerical features (Pre-execution Threat Detection).")

    # 1. Group-based Split (GroupShuffleSplit) by request_hash to prevent data leakage
    gss1 = GroupShuffleSplit(n_splits=1, train_size=0.70, random_state=42)
    train_idx, temp_idx = next(gss1.split(df, df["label"], groups=df["request_hash"]))
    df_train = df.iloc[train_idx].copy()
    df_temp = df.iloc[temp_idx].copy()

    gss2 = GroupShuffleSplit(n_splits=1, train_size=0.50, random_state=42)
    val_idx, test_idx = next(gss2.split(df_temp, df_temp["label"], groups=df_temp["request_hash"]))
    df_val = df_temp.iloc[val_idx].copy()
    df_test = df_temp.iloc[test_idx].copy()

    print(f"\nSplit Sizes -> Train: {len(df_train)} (hashes: {df_train['request_hash'].nunique()}), "
          f"Validation: {len(df_val)} (hashes: {df_val['request_hash'].nunique()}), "
          f"Test: {len(df_test)} (hashes: {df_test['request_hash'].nunique()})")

    print(f"Train distribution: Normal={(df_train['label']==0).sum()}, SQLi={(df_train['label']==1).sum()}")
    print(f"Val distribution:   Normal={(df_val['label']==0).sum()}, SQLi={(df_val['label']==1).sum()}")
    print(f"Test distribution:  Normal={(df_test['label']==0).sum()}, SQLi={(df_test['label']==1).sum()}")

    # Extract numerical arrays
    X_train_num = df_train[numeric_cols].values.astype(np.float32)
    X_val_num = df_val[numeric_cols].values.astype(np.float32)
    X_test_num = df_test[numeric_cols].values.astype(np.float32)

    y_train = df_train["label"].values
    y_val = df_val["label"].values
    y_test = df_test["label"].values

    # 2. Character N-grams TF-IDF Vectorizer (FIT ON X_TRAIN ONLY!)
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=300, min_df=2)
    X_train_tfidf = vectorizer.fit_transform(df_train["text"].tolist())
    X_val_tfidf = vectorizer.transform(df_val["text"].tolist())
    X_test_tfidf = vectorizer.transform(df_test["text"].tolist())

    # Combine Numerical + TF-IDF Features
    X_train_combined = sp.hstack([sp.csr_matrix(X_train_num), X_train_tfidf]).tocsr()
    X_val_combined = sp.hstack([sp.csr_matrix(X_val_num), X_val_tfidf]).tocsr()
    X_test_combined = sp.hstack([sp.csr_matrix(X_test_num), X_test_tfidf]).tocsr()

    # 3. Cross Validation on Train Set (GroupKFold by request_hash)
    gkf = GroupKFold(n_splits=5)
    rf_cv = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced", n_jobs=-1)
    cv_scores = cross_val_score(rf_cv, X_train_combined, y_train, groups=df_train["request_hash"], cv=gkf, scoring="f1_weighted")

    print("\n====================================")
    print("CROSS-VALIDATION RESULTS (GroupKFold)")
    print("====================================")
    print(f"Mean CV F1: {cv_scores.mean():.4f}")
    print(f"Std CV F1:  {cv_scores.std():.4f}")

    # 4. Train Baseline Models (Logistic Regression & Naive Bayes)
    if len(np.unique(y_train)) > 1:
        lr_model = LogisticRegression(max_iter=2000, solver="lbfgs", random_state=42, class_weight="balanced")
        lr_model.fit(X_train_combined, y_train)
        lr_pred_test = lr_model.predict(X_test_combined)
        lr_acc = accuracy_score(y_test, lr_pred_test)

        nb_model = MultinomialNB()
        nb_model.fit(X_train_combined, y_train)
        nb_pred_test = nb_model.predict(X_test_combined)
        nb_acc = accuracy_score(y_test, nb_pred_test)
    else:
        lr_acc = 1.0
        nb_acc = 1.0

    # 5. Train Main Model (Random Forest Classifier)
    rf_model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )
    rf_model.fit(X_train_combined, y_train)

    # 6. Test Set Evaluation
    y_test_pred = rf_model.predict(X_test_combined)
    if len(rf_model.classes_) > 1 and len(np.unique(y_test)) > 1:
        y_test_proba = rf_model.predict_proba(X_test_combined)[:, 1]
        auc_score = roc_auc_score(y_test, y_test_proba)
    else:
        auc_score = 1.0

    acc = accuracy_score(y_test, y_test_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_test_pred, average="binary", pos_label=1, zero_division=0)

    unique_labels = sorted(list(set(y_test) | set(y_test_pred)))
    target_names = ["Normal (0)", "SQLi (1)"] if set(unique_labels) == {0, 1} else None
    report_str = classification_report(
        y_test, y_test_pred, labels=unique_labels, target_names=target_names, digits=4, zero_division=0
    )

    print("\n====================================")
    print("MODEL EVALUATION ON INDEPENDENT TEST SET")
    print("====================================")
    print(f"Baseline Logistic Regression Accuracy: {lr_acc:.4f}")
    print(f"Baseline Multinomial Naive Bayes Acc:  {nb_acc:.4f}")
    print(f"Random Forest Accuracy (Main):         {acc:.4f}")
    print(f"SQLi Precision:                        {prec:.4f}")
    print(f"SQLi Recall (Critical):                {rec:.4f}")
    print(f"SQLi F1-score:                         {f1:.4f}")
    print(f"ROC-AUC Score:                         {auc_score:.4f}")
    print("\nClassification Details:\n")
    print(report_str)

    # Save Reports
    with open(CLASSIFICATION_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("====================================\n")
        f.write("SQL INJECTION RANDOM FOREST MODEL REPORT (AI THREAT DETECTOR)\n")
        f.write("====================================\n\n")
        f.write(f"Total dataset samples: {total_samples}\n")
        f.write(f"Train: {len(df_train)}, Validation: {len(df_val)}, Test: {len(df_test)}\n\n")
        f.write(f"Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})\n")
        f.write(f"Baseline (Logistic Regression) Accuracy: {lr_acc:.4f}\n")
        f.write(f"Baseline (Multinomial NB) Accuracy:      {nb_acc:.4f}\n")
        f.write(f"Random Forest Accuracy:                  {acc:.4f}\n")
        f.write(f"SQLi Precision:                          {prec:.4f}\n")
        f.write(f"SQLi Recall:                             {rec:.4f}\n")
        f.write(f"SQLi F1-score:                           {f1:.4f}\n")
        f.write(f"ROC-AUC Score:                           {auc_score:.4f}\n\n")
        f.write("Classification Details:\n")
        f.write(report_str)

    metrics_dict = {
        "dataset_samples": total_samples,
        "train_samples": len(df_train),
        "validation_samples": len(df_val),
        "test_samples": len(df_test),
        "mean_cv_f1": float(cv_scores.mean()),
        "baseline_lr_accuracy": float(lr_acc),
        "baseline_nb_accuracy": float(nb_acc),
        "accuracy": float(acc),
        "sqli_precision": float(prec),
        "sqli_recall": float(rec),
        "sqli_f1": float(f1),
        "roc_auc": float(auc_score)
    }
    with open(METRICS_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics_dict, f, indent=2)

    # 7. Confusion Matrix Plot
    cm = confusion_matrix(y_test, y_test_pred, labels=[0, 1])
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Normal", "SQLi"],
        yticklabels=["Normal", "SQLi"]
    )
    plt.title("Confusion Matrix - Independent Test Set")
    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Label")
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_FILE, dpi=300)
    plt.close()

    # 8. Feature Importance Analysis
    tfidf_feature_names = [f"tfidf_{feat}" for feat in vectorizer.get_feature_names_out()]
    all_feature_names = numeric_cols + tfidf_feature_names

    importances = rf_model.feature_importances_
    feat_imp_df = pd.DataFrame({
        "feature": all_feature_names,
        "importance": importances
    }).sort_values(by="importance", ascending=False)

    feat_imp_df.to_csv(FEATURE_IMPORTANCE_CSV, index=False, encoding="utf-8")

    # Plot top 25 features
    top_feats = feat_imp_df.head(25)
    plt.figure(figsize=(10, 8))
    sns.barplot(x="importance", y="feature", data=top_feats, hue="feature", legend=False, palette="viridis")
    plt.title("Top 25 Feature Importances (Random Forest)")
    plt.xlabel("Importance Score")
    plt.ylabel("Feature")
    plt.tight_layout()
    plt.savefig(FEATURE_IMPORTANCE_PNG, dpi=300)
    plt.close()

    print(f"Saved feature importances to: {FEATURE_IMPORTANCE_CSV} and {FEATURE_IMPORTANCE_PNG}")

    # 9. Save Model Artifacts
    joblib.dump(rf_model, MODEL_FILE)
    joblib.dump(vectorizer, VEC_FILE)
    joblib.dump(numeric_cols, COLS_FILE)

    print("\n====================================")
    print("SAVED MODEL ARTIFACTS")
    print("====================================")
    print(f"Model:             {MODEL_FILE}")
    print(f"TF-IDF Vectorizer: {VEC_FILE}")
    print(f"Feature Columns:   {COLS_FILE}")

if __name__ == "__main__":
    main()
