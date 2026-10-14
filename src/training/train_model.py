"""
Model Training, Validation, and Evaluation Pipeline for SQL Injection Detection.
Features: Explicit numerical whitelist, template-based group splitting,
independent cross-validation preprocessing, validation threshold tuning,
and audited out-of-distribution benchmark evaluation.
"""
import io
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple, cast

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy.sparse as sp
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.naive_bayes import MultinomialNB

ZERO_DIV: Any = 0

if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import (
    CLASSIFICATION_REPORT_FILE,
    COLS_FILE,
    CONFUSION_MATRIX_FILE,
    FEATURE_IMPORTANCE_PNG,
    FEATURES_CSV,
    METRICS_JSON_FILE,
    MODEL_FILE,
    MODEL_METADATA_FILE,
    MODELS_CURRENT_DIR,
    PAYLOADS_TEST_UNSEEN_CSV,
    REPORTS_DIR,
    VEC_FILE,
)
from src.data_processing.feature_extractor import (
    APPROVED_NUMERICAL_FEATURES,
    extract_features_from_row,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("train_model")


def extract_payload_template(text: str, attack_type: str, label: int, req_hash: str) -> str:
    """
    Construct a canonical group identifier to prevent identical or minor
    template variations from leaking across dataset partitions.
    """
    if label == 0:
        return f"norm_{req_hash}"

    s = str(text).lower()
    s = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", s)
    s = re.sub(r"'[^']*'", "<STR>", s)
    s = re.sub(r'"[^"]*"', "<STR>", s)
    s = re.sub(r"\b\d+\b", "<NUM>", s)
    s = re.sub(r"/\*.*?\*/", "<COMMENT>", s)
    s = re.sub(r"(--|#).*", "<COMMENT>", s)
    s = re.sub(r"\s+", " ", s).strip()
    return f"atk_{attack_type}_{s[:60]}"


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    pos_label: int = 1
) -> Dict[str, Any]:
    """
    Compute binary classification metrics defensively.
    Returns None for undefined metrics (e.g. single-class partition).
    """
    acc = float(accuracy_score(y_true, y_pred))
    p_r_f = precision_recall_fscore_support(
        y_true, y_pred, average="binary", pos_label=pos_label, zero_division=ZERO_DIV
    )
    prec = float(p_r_f[0])
    rec = float(p_r_f[1])
    f1 = float(p_r_f[2])

    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    fpr: Optional[float] = None
    conf_dict: Optional[Dict[str, int]] = None

    unique_classes = np.unique(y_true)
    if len(unique_classes) > 1:
        if y_prob is not None:
            try:
                roc_auc = float(roc_auc_score(y_true, y_prob))
            except Exception:
                roc_auc = None
            try:
                pr_auc = float(average_precision_score(y_true, y_prob))
            except Exception:
                pr_auc = None

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        conf_dict = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "fpr": fpr,
        "confusion_matrix": conf_dict
    }


def run_leakage_free_cv(
    X_num: np.ndarray,
    texts: List[str],
    y: np.ndarray,
    groups: np.ndarray,
    n_splits: int = 5
) -> Tuple[Optional[float], Optional[float]]:
    """
    Perform grouped cross-validation ensuring TF-IDF is fit strictly
    on training folds without validation information leaking into vocabulary or IDF.
    """
    unique_groups = len(np.unique(groups))
    if unique_groups < n_splits:
        logger.warning(f"Too few groups ({unique_groups}) for {n_splits}-fold grouped CV. Skipping CV.")
        return None, None

    gkf = GroupKFold(n_splits=n_splits)
    f1_scores: List[float] = []

    for trn_idx, val_idx in gkf.split(X_num, y, groups=groups):
        y_fold_trn = y[trn_idx]
        y_fold_val = y[val_idx]

        if len(np.unique(y_fold_trn)) < 2:
            continue

        vec_fold = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5), max_features=300, min_df=2
        )
        X_tr_tfidf = vec_fold.fit_transform([texts[i] for i in trn_idx])
        X_va_tfidf = vec_fold.transform([texts[i] for i in val_idx])

        X_tr_comb = sp.hstack([sp.csr_matrix(X_num[trn_idx]), X_tr_tfidf]).tocsr()
        X_va_comb = sp.hstack([sp.csr_matrix(X_num[val_idx]), X_va_tfidf]).tocsr()

        clf = RandomForestClassifier(
            n_estimators=100, random_state=42, class_weight="balanced", n_jobs=-1
        )
        clf.fit(X_tr_comb, y_fold_trn)
        preds = clf.predict(X_va_comb)
        f1_scores.append(float(f1_score(y_fold_val, preds, pos_label=1, zero_division=ZERO_DIV)))

    if not f1_scores:
        return None, None
    return float(np.mean(f1_scores)), float(np.std(f1_scores))


def tune_threshold_on_val(
    y_val: np.ndarray,
    y_val_prob: np.ndarray
) -> Tuple[float, Dict[str, Any]]:
    """
    Select operational classification threshold on validation set.
    Balances SQLi recall and false positive rate.
    """
    candidate_thresholds = np.linspace(0.10, 0.90, 17)
    best_thresh = 0.50
    best_f1 = -1.0
    best_metrics: Dict[str, Any] = {}

    for t in candidate_thresholds:
        preds = (y_val_prob >= t).astype(int)
        m = compute_classification_metrics(y_val, preds, y_val_prob)
        if m["f1"] > best_f1:
            best_f1 = m["f1"]
            best_thresh = round(float(t), 2)
            best_metrics = m

    return best_thresh, best_metrics


def evaluate_unseen_benchmark(
    model: Any,
    vectorizer: Any,
    numeric_cols: List[str],
    unseen_path: Path,
    sqli_idx: int,
    threshold: float
) -> Optional[Dict[str, Any]]:
    """
    Evaluate trained pipeline on independent out-of-distribution payloads (test_unseen.csv).
    Constructs HTTP request representations matching inference contracts.
    """
    if not unseen_path.exists():
        return None

    try:
        df_unseen = pd.read_csv(unseen_path).fillna("")
        if df_unseen.empty or "payload" not in df_unseen.columns or "label" not in df_unseen.columns:
            return None

        unseen_rows: List[List[float]] = []
        unseen_texts: List[str] = []
        actuals: List[int] = [int(v) for v in df_unseen["label"].values]

        for _, row in df_unseen.iterrows():
            raw_payload = str(row["payload"]).strip()
            # If payload already formatted as key=value query string, retain it; otherwise parameterize
            if "=" in raw_payload:
                query_str = raw_payload
            else:
                query_str = f"id={raw_payload}"

            req_dict = {
                "ip": "127.0.0.1",
                "timestamp": "01/Jan/2026:00:00:00 +0000",
                "method": "GET",
                "url": f"/vulnerabilities/sqli/?{query_str}",
                "path": "/vulnerabilities/sqli/",
                "query": query_str,
                "protocol": "HTTP/1.1",
                "status": 200,
                "size": 1024,
                "decoded_url": f"/vulnerabilities/sqli/?{query_str}",
                "decoded_query": query_str,
                "body": "",
                "decoded_body": "",
                "content_type": "",
                "param_count_body": 0
            }
            feat = extract_features_from_row(req_dict)
            unseen_rows.append([float(feat.get(c, 0.0)) for c in numeric_cols])
            unseen_texts.append(str(feat.get("text", "")))

        X_u_num = np.array(unseen_rows, dtype=np.float32)
        X_u_tfidf = vectorizer.transform(unseen_texts)
        X_u_comb = sp.hstack([sp.csr_matrix(X_u_num), X_u_tfidf]).tocsr()

        probas = cast(np.ndarray, model.predict_proba(X_u_comb))
        sqli_probas = probas[:, sqli_idx] if probas.shape[1] > sqli_idx else probas[:, -1]
        preds = (sqli_probas >= threshold).astype(int)

        metrics = compute_classification_metrics(np.array(actuals), preds, sqli_probas)
        metrics["samples"] = len(df_unseen)
        return metrics
    except Exception as e:
        logger.warning(f"Unseen benchmark evaluation encountered error: {e}")
        return None


def main():
    MODELS_CURRENT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if not FEATURES_CSV.exists():
        logger.error(f"Features file {FEATURES_CSV} not found. Run feature_extractor.py first.")
        sys.exit(1)

    # 1. Dataset Ingestion & Whitelist Schema Validation
    df = pd.read_csv(FEATURES_CSV).fillna("")
    total_samples = len(df)
    if total_samples < 50:
        logger.error(f"Dataset too small ({total_samples} samples) to train reliable model.")
        sys.exit(1)

    missing_schema = [col for col in APPROVED_NUMERICAL_FEATURES if col not in df.columns]
    if missing_schema:
        logger.error(f"Schema mismatch: missing {len(missing_schema)} required numerical features: {missing_schema[:5]}")
        sys.exit(1)

    numeric_cols = list(APPROVED_NUMERICAL_FEATURES)

    # Validate non-finite and data types
    try:
        X_num_all = df[numeric_cols].values.astype(np.float32)
        if not np.all(np.isfinite(X_num_all)):
            logger.error("Dataset contains NaN or infinite values in numerical features.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to convert numerical features to float32: {e}")
        sys.exit(1)

    y_all: np.ndarray = np.array(df["label"].tolist(), dtype=np.int64)
    unique_labels = sorted(list(np.unique(y_all)))
    if set(unique_labels) != {0, 1}:
        logger.error(f"Dataset must contain binary labels {0, 1}, found: {unique_labels}")
        sys.exit(1)

    normal_count = int(np.count_nonzero(y_all == 0))
    sqli_count = int(np.count_nonzero(y_all == 1))

    # 2. Defensible Group-based Split (Preventing Variant & Duplicate Leakage)
    df["split_group"] = [
        extract_payload_template(t, a, l, h)
        for t, a, l, h in zip(df["text"], df["attack_type"], df["label"], df["request_hash"])
    ]
    groups_all: np.ndarray = np.array(df["split_group"].tolist())

    gss1 = GroupShuffleSplit(n_splits=1, train_size=0.70, random_state=42)
    train_idx, temp_idx = next(gss1.split(df, y_all, groups=groups_all))
    df_train = df.iloc[train_idx].copy()
    df_temp = df.iloc[temp_idx].copy()

    gss2 = GroupShuffleSplit(n_splits=1, train_size=0.50, random_state=42)
    y_temp: np.ndarray = np.array(df_temp["label"].tolist(), dtype=np.int64)
    groups_temp: np.ndarray = np.array(df_temp["split_group"].tolist())
    val_idx, test_idx = next(gss2.split(df_temp, y_temp, groups=groups_temp))
    df_val = df_temp.iloc[val_idx].copy()
    df_test = df_temp.iloc[test_idx].copy()

    # Validate split partitions
    for part_name, part_df in [("Train", df_train), ("Validation", df_val), ("Test", df_test)]:
        p_labels = set(np.unique(np.array(part_df["label"].tolist(), dtype=np.int64)))
        if p_labels != {0, 1}:
            logger.error(f"{part_name} split lacks representation for both classes (found {p_labels}).")
            sys.exit(1)

    X_train_num = df_train[numeric_cols].values.astype(np.float32)
    X_val_num = df_val[numeric_cols].values.astype(np.float32)
    X_test_num = df_test[numeric_cols].values.astype(np.float32)

    y_train = df_train["label"].values
    y_val = df_val["label"].values
    y_test = df_test["label"].values

    train_texts = df_train["text"].tolist()
    val_texts = df_val["text"].tolist()
    test_texts = df_test["text"].tolist()

    # 3. Leakage-Free Cross-Validation
    cv_mean, cv_std = run_leakage_free_cv(
        X_train_num, train_texts, y_train, df_train["split_group"].values, n_splits=5
    )

    # 4. Final Text Vectorization (Fitted strictly on train set)
    vectorizer = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5), max_features=300, min_df=2
    )
    X_train_tfidf = vectorizer.fit_transform(train_texts)
    X_val_tfidf = vectorizer.transform(val_texts)
    X_test_tfidf = vectorizer.transform(test_texts)

    X_train_comb = sp.hstack([sp.csr_matrix(X_train_num), X_train_tfidf]).tocsr()
    X_val_comb = sp.hstack([sp.csr_matrix(X_val_num), X_val_tfidf]).tocsr()
    X_test_comb = sp.hstack([sp.csr_matrix(X_test_num), X_test_tfidf]).tocsr()

    # 5. Train Baseline Models
    lr_model = LogisticRegression(max_iter=2000, solver="lbfgs", random_state=42, class_weight="balanced")
    lr_model.fit(X_train_comb, y_train)
    lr_test_preds = np.asarray(lr_model.predict(X_test_comb), dtype=np.int64)
    lr_metrics = compute_classification_metrics(y_test, lr_test_preds)

    nb_model = MultinomialNB()
    nb_model.fit(X_train_comb, y_train)
    nb_test_preds = np.asarray(nb_model.predict(X_test_comb), dtype=np.int64)
    nb_metrics = compute_classification_metrics(y_test, nb_test_preds)

    # 6. Train Primary Random Forest Model
    rf_model = RandomForestClassifier(
        n_estimators=300, random_state=42, class_weight="balanced", n_jobs=-1
    )
    rf_model.fit(X_train_comb, y_train)

    rf_classes = list(rf_model.classes_)
    if 1 not in rf_classes:
        logger.error("Random Forest trained model missing target SQLi class (label 1).")
        sys.exit(1)
    sqli_idx = rf_classes.index(1)

    # 7. Validation Evaluation & Threshold Tuning
    val_probas = cast(np.ndarray, rf_model.predict_proba(X_val_comb))[:, sqli_idx]
    optimal_threshold, val_metrics = tune_threshold_on_val(y_val, val_probas)

    # 8. Independent Test Evaluation with Selected Threshold
    test_probas = cast(np.ndarray, rf_model.predict_proba(X_test_comb))[:, sqli_idx]
    test_preds = (test_probas >= optimal_threshold).astype(int)
    rf_test_metrics = compute_classification_metrics(y_test, test_preds, test_probas)

    # 9. Out-of-Distribution Unseen Benchmark Evaluation
    unseen_metrics = evaluate_unseen_benchmark(
        rf_model, vectorizer, numeric_cols, PAYLOADS_TEST_UNSEEN_CSV, sqli_idx, optimal_threshold
    )

    # 10. Generate and Save Reports & Visualizations
    cm = confusion_matrix(y_test, test_preds, labels=[0, 1])
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Normal", "SQLi"], yticklabels=["Normal", "SQLi"])
    plt.title("Confusion Matrix — Independent Test Set")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_FILE, dpi=300)
    plt.close()

    # Feature Importance
    tfidf_names = [f"tfidf_{name}" for name in vectorizer.get_feature_names_out()]
    all_feature_names = numeric_cols + tfidf_names
    importances = rf_model.feature_importances_
    feat_imp_df = pd.DataFrame({
        "feature": all_feature_names,
        "importance": importances
    }).sort_values(by="importance", ascending=False)

    plt.figure(figsize=(8, 6))
    top_feats = feat_imp_df.head(20)
    sns.barplot(x="importance", y="feature", data=top_feats, hue="feature", legend=False, palette="viridis")
    plt.title("Top 20 Features (Random Forest)")
    plt.xlabel("Importance Score")
    plt.ylabel("Feature")
    plt.tight_layout()
    plt.savefig(FEATURE_IMPORTANCE_PNG, dpi=300)
    plt.close()

    # Detailed Classification Report
    target_names = ["Normal (0)", "SQLi (1)"]
    report_text = classification_report(
        y_test, test_preds, labels=[0, 1], target_names=target_names, digits=4, zero_division=ZERO_DIV
    )
    with open(CLASSIFICATION_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("SQL INJECTION DETECTION — EVALUATION REPORT\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Total samples: {total_samples} (Train: {len(df_train)}, Val: {len(df_val)}, Test: {len(df_test)})\n")
        f.write(f"Cross-validation F1 (5-Fold Grouped): {cv_mean:.4f} ± {cv_std:.4f}\n" if cv_mean is not None else "CV: N/A\n")
        f.write(f"Selected Threshold: {optimal_threshold:.2f}\n\n")
        f.write("Test Set Classification Details:\n")
        f.write(str(report_text) + "\n\n")
        if unseen_metrics:
            f.write("Unseen Payloads Benchmark:\n")
            f.write(f"Samples: {unseen_metrics.get('samples')}\n")
            f.write(f"Accuracy: {unseen_metrics.get('accuracy', 0.0) * 100:.2f}%\n")
            f.write(f"Recall: {unseen_metrics.get('recall', 0.0) * 100:.2f}%\n")
            f.write(f"Precision: {unseen_metrics.get('precision', 0.0) * 100:.2f}%\n")
            f.write(f"F1-Score: {unseen_metrics.get('f1', 0.0) * 100:.2f}%\n")

    # Metrics JSON
    metrics_json_content = {
        "dataset_samples": total_samples,
        "train_samples": len(df_train),
        "validation_samples": len(df_val),
        "test_samples": len(df_test),
        "selected_threshold": optimal_threshold,
        "cv_f1_mean": cv_mean,
        "cv_f1_std": cv_std,
        "validation_metrics": val_metrics,
        "test_metrics": {
            "logistic_regression": lr_metrics,
            "multinomial_nb": nb_metrics,
            "random_forest": rf_test_metrics
        },
        "unseen_benchmark": unseen_metrics
    }
    with open(METRICS_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics_json_content, f, indent=2)

    # 11. Save Model Artifacts
    joblib.dump(rf_model, MODEL_FILE)
    joblib.dump(vectorizer, VEC_FILE)
    joblib.dump(numeric_cols, COLS_FILE)

    metadata_dict = {
        "model_version": "1.1.0",
        "algorithm": "Random Forest Classifier",
        "selected_threshold": optimal_threshold,
        "default_threshold": optimal_threshold,
        "features": {
            "numerical_feature_count": len(numeric_cols),
            "tfidf_feature_count": len(vectorizer.get_feature_names_out()),
            "total_feature_dim": len(numeric_cols) + len(vectorizer.get_feature_names_out())
        },
        "dataset_split_strategy": "GroupShuffleSplit on template-based payload family and canonical request hash",
        "train_samples": len(df_train),
        "validation_samples": len(df_val),
        "test_samples": len(df_test),
        "metrics": {
            "accuracy": rf_test_metrics["accuracy"],
            "sqli_recall": rf_test_metrics["recall"],
            "sqli_precision": rf_test_metrics["precision"],
            "sqli_f1": rf_test_metrics["f1"],
            "roc_auc": rf_test_metrics["roc_auc"],
            "pr_auc": rf_test_metrics["pr_auc"],
            "fpr": rf_test_metrics["fpr"]
        }
    }
    with open(MODEL_METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=2)

    # 12. Compact Terminal Output (Section 5 Standard)
    print("\nSQLi Detection — Training\n")
    print(f"Dataset   {total_samples:,} samples | Normal {normal_count:,} | SQLi {sqli_count:,}")
    print(
        f"Split     Train {len(df_train):,} ({len(df_train)/total_samples*100:.1f}%) | "
        f"Validation {len(df_val):,} ({len(df_val)/total_samples*100:.1f}%) | "
        f"Test {len(df_test):,} ({len(df_test)/total_samples*100:.1f}%)"
    )
    print(f"Features  {len(numeric_cols)} numeric + {len(vectorizer.get_feature_names_out())} TF-IDF")
    print("Model     Random Forest | 300 trees")

    print("\nCross-validation (5-Fold Grouped)")
    if cv_mean is not None and cv_std is not None:
        print(f"F1        {cv_mean:.4f} ± {cv_std:.4f}")
    else:
        print("F1        N/A")

    print("\nValidation threshold tuning")
    print(
        f"Selected threshold: {optimal_threshold:.2f} "
        f"(F1: {val_metrics.get('f1', 0.0):.4f}, Recall: {val_metrics.get('recall', 0.0)*100:.2f}%, FPR: {val_metrics.get('fpr', 0.0)*100:.2f}%)"
    )

    print("\nTest results (Independent Test Set)")
    header = f"{'Model':<21} {'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8}"
    print(header)
    print("-" * 57)
    print(
        f"{'Logistic Regression':<21} "
        f"{lr_metrics['accuracy']*100:>7.2f}% "
        f"{lr_metrics['precision']*100:>7.2f}% "
        f"{lr_metrics['recall']*100:>7.2f}% "
        f"{lr_metrics['f1']*100:>7.2f}%"
    )
    print(
        f"{'Naive Bayes':<21} "
        f"{nb_metrics['accuracy']*100:>7.2f}% "
        f"{nb_metrics['precision']*100:>7.2f}% "
        f"{nb_metrics['recall']*100:>7.2f}% "
        f"{nb_metrics['f1']*100:>7.2f}%"
    )
    print(
        f"{'Random Forest':<21} "
        f"{rf_test_metrics['accuracy']*100:>7.2f}% "
        f"{rf_test_metrics['precision']*100:>7.2f}% "
        f"{rf_test_metrics['recall']*100:>7.2f}% "
        f"{rf_test_metrics['f1']*100:>7.2f}%"
    )
    print("-" * 57)
    print(f"SQLi Recall   {rf_test_metrics['recall']*100:.2f}%")
    print(f"PR-AUC        {rf_test_metrics['pr_auc']:.4f}" if rf_test_metrics['pr_auc'] is not None else "PR-AUC        N/A")
    print(f"ROC-AUC       {rf_test_metrics['roc_auc']:.4f}" if rf_test_metrics['roc_auc'] is not None else "ROC-AUC       N/A")
    print(f"FPR           {rf_test_metrics['fpr']*100:.2f}%" if rf_test_metrics['fpr'] is not None else "FPR           N/A")

    if unseen_metrics:
        print("\nUnseen payloads benchmark")
        print(f"Samples       {unseen_metrics.get('samples'):,}")
        print(f"Recall        {unseen_metrics.get('recall', 0.0)*100:.2f}%")
        print(f"Precision     {unseen_metrics.get('precision', 0.0)*100:.2f}%")
        print(f"F1            {unseen_metrics.get('f1', 0.0)*100:.2f}%")
        print(f"Accuracy      {unseen_metrics.get('accuracy', 0.0)*100:.2f}%")

    print("\nArtifacts")
    print(f"Model         {MODEL_FILE}")
    print(f"Vectorizer    {VEC_FILE}")
    print(f"Feature list  {COLS_FILE}")
    print(f"Metadata      {MODEL_METADATA_FILE}")
    print(f"Metrics       {METRICS_JSON_FILE}")
    print(f"Report        {CLASSIFICATION_REPORT_FILE}")

    print("\nStatus: SUCCESS\n")


if __name__ == "__main__":
    main()
