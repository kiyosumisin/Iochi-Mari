import sys
import os
import logging
import argparse
from pathlib import Path

# Add the project root directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    average_precision_score,
)
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

from ai.feature_extractor import extract_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _get_feature_version(sample_feats: dict) -> str:
    """Version đơn giản dựa trên tên các feature (không tính 'url')."""
    return ",".join(sorted(k for k in sample_feats if k != "url"))


def main():
    parser = argparse.ArgumentParser(description="Train URL malicious classifier")
    parser.add_argument(
        "--with-page",
        action="store_true",
        default=False,
        help="Fetch nội dung trang để thêm HTML feature (chậm hơn, chính xác hơn)",
    )
    args = parser.parse_args()
    include_page = args.with_page

    if include_page:
        logger.info("Chế độ: URL features + Page content features (--with-page)")
    else:
        logger.info("Chế độ: URL features only (dùng --with-page để thêm HTML features)")

    # ===== Resolve dataset path =====
    BASE_DIR = Path(__file__).resolve().parent
    DATA_PATH = BASE_DIR / "data" / "urls.csv"

    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    # ===== Load dataset =====
    df = pd.read_csv(DATA_PATH)

    # ===== Normalize + validate columns =====
    df.columns = [col.strip().lower() for col in df.columns]
    if "labels" in df.columns and "label" not in df.columns:
        df = df.rename(columns={"labels": "label"})
    if "urls" in df.columns and "url" not in df.columns:
        df = df.rename(columns={"urls": "url"})

    required_cols = {"url", "label"}
    if not required_cols.issubset(df.columns):
        raise ValueError(
            f"CSV must contain columns: {required_cols}. Found: {set(df.columns)}"
        )

    logger.info(f"Loaded {len(df)} rows. Label distribution:\n{df['label'].value_counts()}")

    # ===== Feature extraction =====
    rows = []
    y = []

    for _, row in df.iterrows():
        url = str(row["url"])
        try:
            feats = extract_features(url, include_page=include_page)
        except ValueError as e:
            logger.warning(f"Skipping invalid URL: {e}")
            continue
        feats["url"] = url
        rows.append(feats)
        y.append(int(row["label"]))

    X = pd.DataFrame(rows)
    y = pd.Series(y)

    # Lấy feature version từ sample đầu tiên
    feature_version = _get_feature_version(rows[0])
    logger.info(f"Feature version: {feature_version}")

    # ===== Train / Test split =====
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # ===== Build model pipeline =====
    numeric_features = [col for col in X.columns if col != "url"]

    model = Pipeline(
        steps=[
            (
                "preprocess",
                ColumnTransformer(
                    transformers=[
                        (
                            "url_tfidf",
                            TfidfVectorizer(analyzer="char"),
                            "url"
                        ),
                        (
                            "num",
                            StandardScaler(with_mean=False),
                            numeric_features
                        ),
                    ],
                    remainder="drop",
                    sparse_threshold=0.3
                )
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=5000,
                    tol=1e-3,          # relax tolerance slightly to help convergence
                    class_weight="balanced",
                    n_jobs=1,
                    solver="saga"
                )
            ),
        ]
    )

    # ===== Hyperparameter search =====
    param_grid = {
        "preprocess__url_tfidf__ngram_range": [(3, 4), (3, 5), (4, 5)],
        "preprocess__url_tfidf__min_df": [2, 3],
        "preprocess__url_tfidf__max_features": [3000, 5000, 8000],
        "clf__C": [0.5, 1.0, 2.0, 4.0],
        "clf__tol": [1e-3, 1e-4],   # search over tolerance as well
    }

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    search = GridSearchCV(
        model,
        param_grid=param_grid,
        scoring="f1",
        cv=cv,
        n_jobs=-1,
        verbose=1
    )

    search.fit(X_train, y_train)
    model = search.best_estimator_
    logger.info(f"Best params: {search.best_params_}")

    # ===== Evaluation =====
    y_pred = model.predict(X_test)
    classes = list(getattr(model, "classes_", []))
    malicious_label = int(os.getenv("AI_MALICIOUS_LABEL", "0"))
    if malicious_label in classes:
        mal_idx = classes.index(malicious_label)
    else:
        mal_idx = 1 if len(classes) > 1 else 0
    y_prob = model.predict_proba(X_test)[:, mal_idx]
    y_true_mal = (y_test == malicious_label).astype(int)

    # ===== Threshold optimization =====
    precision, recall, thresholds = precision_recall_curve(y_true_mal, y_prob)
    f1_scores = (2 * precision * recall) / (precision + recall + 1e-12)
    best_idx = f1_scores.argmax()
    best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
    y_pred_opt = (y_prob >= best_threshold).astype(int)

    print("=== Confusion Matrix (Default 0.5, original labels) ===")
    print(confusion_matrix(y_test, y_pred))

    print("\n=== Classification Report (Default 0.5, original labels) ===")
    print(classification_report(y_test, y_pred, digits=4))

    print(f"\nBest threshold (F1) for malicious label={malicious_label}: {best_threshold:.4f}")
    print("=== Confusion Matrix (Optimized, malicious=1) ===")
    print(confusion_matrix(y_true_mal, y_pred_opt))

    print("\n=== Classification Report (Optimized, malicious=1) ===")
    print(classification_report(y_true_mal, y_pred_opt, digits=4))

    print(f"\nROC AUC (malicious): {roc_auc_score(y_true_mal, y_prob):.4f}")
    print(f"Average Precision (PR AUC, malicious): {average_precision_score(y_true_mal, y_prob):.4f}")

    # ===== Save model =====
    model_path = BASE_DIR / "model.pkl"
    payload = {
        "model": model,
        "meta": {
            "malicious_label": malicious_label,
            "best_threshold": best_threshold,
            "feature_version": feature_version,
            "include_page": include_page,   # lưu để predict biết mode nào đã train
        },
    }
    joblib.dump(payload, model_path)
    logger.info(f"Model saved to {model_path} (threshold={best_threshold:.4f})")

    # ===== Quick manual test =====
    test_url = "http://vip-zone2026.site/login"
    test_feats = extract_features(test_url)
    test_feats["url"] = test_url
    test_df = pd.DataFrame([test_feats])

    test_proba = model.predict_proba(test_df)[0]
    prob = float(test_proba[mal_idx])
    logger.info(f"Test URL: {test_url}")
    logger.info(f"Malicious probability: {prob:.4f}")


if __name__ == "__main__":
    main()