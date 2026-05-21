"""
train.py
--------
Train a LightGBM malicious URL classifier.

Pipeline
--------
  URL string  -> TF-IDF char n-grams  ]
  14 numeric  -> StandardScaler       ] -> LGBMClassifier -> threshold-optimised model.pkl
  (optional)  -> page-content feats   ]

Usage
-----
  python -m ai.train                  # URL features only (fast)
  python -m ai.train --with-page      # + live HTML fetch (slower, more accurate)
  python -m ai.train --data path/to/urls.csv
  python -m ai.train --feedback       # merge feedback.csv into training set before fitting
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import warnings
from pathlib import Path

# LightGBM was trained with feature names (DataFrame), but sklearn's internal
# cross-validation passes raw numpy arrays between pipeline steps — triggering
# this warning on every single CV fold fit. It is cosmetic only (results are
# correct), so we suppress it globally for this training script.
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
    module="sklearn",
)

# Ensure project root is on sys.path when run as a script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ai.feature_extractor import extract_features

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_PATH = BASE_DIR / "data" / "urls.csv"
DEFAULT_FEEDBACK_PATH = BASE_DIR / "feedback.csv"
DEFAULT_MODEL_PATH = BASE_DIR / "model.pkl"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_feature_version(sample_feats: dict) -> str:
    """Fingerprint the feature set by sorted key names (excluding 'url')."""
    return ",".join(sorted(k for k in sample_feats if k != "url"))


def _load_and_validate_csv(path: Path) -> pd.DataFrame:
    """Load a CSV, normalise column names, and enforce required columns."""
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]

    # Accept common column name variants
    if "labels" in df.columns and "label" not in df.columns:
        df = df.rename(columns={"labels": "label"})
    if "urls" in df.columns and "url" not in df.columns:
        df = df.rename(columns={"urls": "url"})

    missing = {"url", "label"} - set(df.columns)
    if missing:
        raise ValueError(f"CSV {path} is missing columns: {missing}. Found: {set(df.columns)}")

    return df


def _extract_features_parallel(
    df: pd.DataFrame,
    include_page: bool,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Extract features from every URL row, skipping invalid entries.
    Returns (X DataFrame, y Series).
    """
    rows: list[dict] = []
    labels: list[int] = []

    for _, row in df.iterrows():
        url = str(row["url"]).strip()
        try:
            feats = extract_features(url, include_page=include_page)
        except ValueError as exc:
            logger.warning("Skipping invalid URL %r: %s", url, exc)
            continue
        feats["url"] = url
        rows.append(feats)
        labels.append(int(row["label"]))

    if not rows:
        raise RuntimeError("No valid URLs were extracted — check your dataset.")

    return pd.DataFrame(rows), pd.Series(labels)


def _build_pipeline(numeric_features: list[str]) -> Pipeline:
    """
    Construct the sklearn Pipeline:
      preprocess: TF-IDF (char n-grams on URL string) + StandardScaler (numeric)
      clf:        LGBMClassifier
    """
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "url_tfidf",
                TfidfVectorizer(analyzer="char"),
                "url",
            ),
            (
                "num",
                StandardScaler(with_mean=False),  # sparse-safe
                numeric_features,
            ),
        ],
        remainder="drop",
        sparse_threshold=0.3,
    )

    classifier = LGBMClassifier(
        boosting_type="gbdt",
        objective="binary",
        class_weight="balanced",   # handles label imbalance (same as LR was doing)
        n_jobs=-1,
        verbose=-1,                # suppress LightGBM stdout chatter
        random_state=42,
    )

    return Pipeline(steps=[("preprocess", preprocessor), ("clf", classifier)])


def _param_grid(fast: bool = False) -> dict:
    """
    GridSearchCV search space.

    fast=False (default): 864 combinations — thorough, full CPU, ~20-60 min.
    fast=True           : 8 combinations   — quick smoke-test, ~2-5 min.
    """
    if fast:
        return {
            "preprocess__url_tfidf__ngram_range": [(3, 5)],
            "preprocess__url_tfidf__min_df": [2],
            "preprocess__url_tfidf__max_features": [5000],
            "clf__n_estimators": [200],
            "clf__max_depth": [6, 10],
            "clf__learning_rate": [0.05, 0.1],
            "clf__min_child_samples": [20],
        }
    return {
        # Preprocessing
        "preprocess__url_tfidf__ngram_range": [(3, 4), (3, 5), (4, 5)],
        "preprocess__url_tfidf__min_df": [2, 3],
        "preprocess__url_tfidf__max_features": [3000, 5000, 8000],
        # LightGBM
        "clf__n_estimators": [200, 400],
        "clf__max_depth": [6, 10, -1],
        "clf__learning_rate": [0.05, 0.1],
        "clf__min_child_samples": [10, 20],
    }


def _optimise_threshold(
    y_true: pd.Series,
    y_prob: np.ndarray,
    malicious_label: int,
) -> tuple[float, np.ndarray]:
    """
    Find the probability threshold that maximises F1 on the test set.
    Returns (best_threshold, binary_predictions_at_best_threshold).
    """
    y_true_binary = (y_true == malicious_label).astype(int)
    precision, recall, thresholds = precision_recall_curve(y_true_binary, y_prob)
    f1 = (2 * precision * recall) / (precision + recall + 1e-12)
    best_idx = int(f1.argmax())
    best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
    y_pred_opt = (y_prob >= best_threshold).astype(int)
    return best_threshold, y_pred_opt


def _print_evaluation(
    y_test: pd.Series,
    y_pred_default: np.ndarray,
    y_true_binary: np.ndarray,
    y_pred_opt: np.ndarray,
    y_prob: np.ndarray,
    malicious_label: int,
    best_threshold: float,
) -> None:
    """Print confusion matrices, classification reports, and AUC scores."""
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)

    print("\n--- Confusion Matrix (default threshold=0.5, original labels) ---")
    print(confusion_matrix(y_test, y_pred_default))

    print("\n--- Classification Report (default threshold=0.5) ---")
    print(classification_report(y_test, y_pred_default, digits=4))

    print(f"\n--- Optimised threshold (max-F1) for malicious label={malicious_label}: "
          f"{best_threshold:.4f} ---")
    print("Confusion Matrix (optimised threshold, malicious=1):")
    print(confusion_matrix(y_true_binary, y_pred_opt))

    print("\nClassification Report (optimised threshold):")
    print(classification_report(y_true_binary, y_pred_opt, digits=4))

    print(f"\nROC AUC  : {roc_auc_score(y_true_binary, y_prob):.4f}")
    print(f"PR  AUC  : {average_precision_score(y_true_binary, y_prob):.4f}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Train LightGBM malicious URL classifier")
    parser.add_argument(
        "--with-page",
        action="store_true",
        default=False,
        help="Fetch page content for extra HTML features (slower, more accurate)",
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help=f"Path to training CSV (default: {DEFAULT_DATA_PATH})",
    )
    parser.add_argument(
        "--feedback",
        action="store_true",
        default=False,
        help="Merge feedback.csv into the training set before fitting",
    )
    parser.add_argument(
        "--feedback-path",
        type=Path,
        default=DEFAULT_FEEDBACK_PATH,
        help=f"Path to feedback CSV (default: {DEFAULT_FEEDBACK_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help=f"Where to save the model (default: {DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        default=False,
        help=(
            "Use a smaller param grid (8 combos vs 864). "
            "Much faster, slightly less optimal. Good for testing."
        ),
    )
    parser.add_argument(
        "--cpu-cores",
        type=int,
        default=-1,
        metavar="N",
        help=(
            "Number of CPU cores for GridSearchCV (default: -1 = all cores). "
            "Use e.g. --cpu-cores 2 to reduce CPU load on your machine."
        ),
    )
    args = parser.parse_args()

    include_page = args.with_page
    mode_label = "URL + page-content" if include_page else "URL-only"
    logger.info("Mode: %s", mode_label)

    # ── Load dataset ──────────────────────────────────────────────────────────
    if not args.data.exists():
        raise FileNotFoundError(f"Dataset not found: {args.data}")

    df = _load_and_validate_csv(args.data)
    logger.info("Loaded %d rows from %s", len(df), args.data)
    logger.info("Label distribution:\n%s", df["label"].value_counts().to_string())

    # ── Merge feedback if requested ───────────────────────────────────────────
    if args.feedback:
        if not args.feedback_path.exists():
            logger.warning(
                "--feedback requested but %s not found — skipping merge.", args.feedback_path
            )
        else:
            fb = _load_and_validate_csv(args.feedback_path)
            # feedback.csv may have a 'timestamp' column — drop it
            fb = fb[["url", "label"]].copy()
            before = len(df)
            df = pd.concat([df, fb], ignore_index=True).drop_duplicates(subset="url")
            logger.info(
                "Merged feedback: %d rows → %d rows (+%d unique)",
                before, len(df), len(df) - before,
            )

    # ── Feature extraction ────────────────────────────────────────────────────
    logger.info("Extracting features (include_page=%s) …", include_page)
    X, y = _extract_features_parallel(df, include_page=include_page)

    feature_version = _get_feature_version(X.iloc[0].to_dict())
    logger.info("Feature set: %d columns | version: %s", len(X.columns), feature_version)

    # ── Train / test split ────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info("Train: %d rows | Test: %d rows", len(X_train), len(X_test))

    # ── Build pipeline + hyperparameter search ────────────────────────────────
    numeric_features = [col for col in X.columns if col != "url"]
    pipeline = _build_pipeline(numeric_features)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    param_grid = _param_grid(fast=args.fast)
    n_combinations = 1
    for v in param_grid.values():
        n_combinations *= len(v)
    logger.info(
        "GridSearchCV: %d combinations x 5 folds = %d fits | cores=%s | fast=%s",
        n_combinations, n_combinations * 5, args.cpu_cores, args.fast,
    )
    search = GridSearchCV(
        pipeline,
        param_grid=param_grid,
        scoring="f1",
        cv=cv,
        n_jobs=args.cpu_cores,
        verbose=1,
        refit=True,
    )

    logger.info("Starting GridSearchCV …")
    search.fit(X_train, y_train)
    best_model = search.best_estimator_
    logger.info("Best CV F1 : %.4f", search.best_score_)
    logger.info("Best params: %s", search.best_params_)

    # ── Evaluation ────────────────────────────────────────────────────────────
    malicious_label = int(os.getenv("AI_MALICIOUS_LABEL", "0"))
    classes = list(best_model.classes_)
    mal_idx = (
        classes.index(malicious_label) if malicious_label in classes
        else (1 if len(classes) > 1 else 0)
    )

    y_pred_default = best_model.predict(X_test)
    y_prob = best_model.predict_proba(X_test)[:, mal_idx]
    y_true_binary = (y_test == malicious_label).astype(int)

    best_threshold, y_pred_opt = _optimise_threshold(y_test, y_prob, malicious_label)

    _print_evaluation(
        y_test=y_test,
        y_pred_default=y_pred_default,
        y_true_binary=y_true_binary,
        y_pred_opt=y_pred_opt,
        y_prob=y_prob,
        malicious_label=malicious_label,
        best_threshold=best_threshold,
    )

    # ── Save model ────────────────────────────────────────────────────────────
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": best_model,
        "meta": {
            "model_type": "lgbm",               # used by predict.py to choose explainer
            "malicious_label": malicious_label,
            "best_threshold": best_threshold,
            "feature_version": feature_version,
            "include_page": include_page,
            "best_cv_f1": round(float(search.best_score_), 6),
            "best_params": search.best_params_,
        },
    }
    joblib.dump(payload, args.output)
    logger.info("Model saved → %s  (threshold=%.4f)", args.output, best_threshold)

    # ── Quick sanity check ────────────────────────────────────────────────────
    test_url = "http://vip-zone2026.site/login"
    test_feats = extract_features(test_url)
    test_feats["url"] = test_url
    test_df = pd.DataFrame([test_feats])
    prob = float(best_model.predict_proba(test_df)[0, mal_idx])
    logger.info("Sanity check | %s → malicious probability: %.4f", test_url, prob)


if __name__ == "__main__":
    main()