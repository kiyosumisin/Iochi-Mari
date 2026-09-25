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
import random
import re
import sys
import urllib.request
import warnings
import zipfile
from pathlib import Path
from urllib.parse import urlparse

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
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    GridSearchCV,
    StratifiedGroupKFold,
    cross_val_predict,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ai.feature_extractor import extract_features
from core.scam_list import OWNED, SOURCES, ScamDomainList, parse_domains

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
FP_TARGET = 0.05  # max out-of-fold false-positive rate allowed when picking the threshold
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_PATH = BASE_DIR / "data" / "tranco.zip"  # gitignored download cache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_feature_version(sample_feats: dict) -> str:
    """Fingerprint the feature set by sorted key names (excluding 'url')."""
    return ",".join(sorted(k for k in sample_feats if k != "url"))


# Second-level labels that sit under a ccTLD, e.g. "co.uk", "com.vn".
_SLD_UNDER_CCTLD = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob"}


def _registered_domain(url: str) -> str:
    """
    Best-effort eTLD+1 (registered domain), used ONLY to group URLs so the same
    site never lands in both train and test. Not a full public-suffix parse, but
    enough to prevent domain leakage. IPs group by themselves.
    """
    host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    if not host:
        return url  # fall back to the raw string as its own group
    if host.replace(".", "").isdigit() or ":" in host:  # IPv4 / IPv6
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # bbc.co.uk / foo.com.vn → keep 3 labels; otherwise keep the last 2.
    if len(parts[-1]) == 2 and parts[-2] in _SLD_UNDER_CCTLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _family(url: str) -> str:
    """Group key for CV: letters of the registered name only, so look-alike
    siblings (discord-nitro1.com, discordnitro2.xyz -> "discordnitro") always
    land on the same side of a split instead of leaking between train/test."""
    rd = _registered_domain(url)
    return re.sub(r"[^a-z]", "", rd.split(".")[0]) or rd


def _augmentation_rows(malicious_label: int) -> pd.DataFrame:
    """Community Discord scam domains (malicious) balanced by an equal number of
    Tranco top-200k domains (benign), all as bare https://domain/ URLs so the
    two classes share the same shape and the model can't learn "no path = scam"."""
    guard = ScamDomainList.__new__(ScamDomainList)
    guard.protected = set(OWNED)
    scam = set()
    for url in SOURCES:
        scam |= parse_domains(urllib.request.urlopen(url, timeout=60).read().decode("utf-8", "ignore"))
    scam = {d for d in scam if not guard.is_protected(d)}

    if not TRANCO_PATH.exists():
        logger.info("Downloading Tranco list → %s", TRANCO_PATH)
        urllib.request.urlretrieve(TRANCO_URL, TRANCO_PATH)
    lines = zipfile.ZipFile(TRANCO_PATH).open("top-1m.csv").read().decode().splitlines()
    pool = [ln.split(",", 1)[1].strip().lower() for ln in lines[:200_000]]
    pool = [d for d in pool if d not in scam]
    benign = random.Random(42).sample(pool, min(len(scam), len(pool)))

    logger.info("Augmentation: %d scam domains + %d benign Tranco domains", len(scam), len(benign))
    return pd.DataFrame(
        [{"url": f"https://{d}/", "label": malicious_label} for d in sorted(scam)]
        + [{"url": f"https://{d}/", "label": 1 - malicious_label} for d in benign]
    )


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

    Regularised on purpose (anti-overfitting): capped depth/leaves, row and
    column subsampling, L2, large leaves and a TF-IDF min_df that ignores rare
    n-grams, so the model can't memorise individual domains.

    fast=False (default): 8 combinations.
    fast=True           : 2 combinations around the validated configuration.
    """
    base = {
        "preprocess__url_tfidf__ngram_range": [(3, 5)],
        "preprocess__url_tfidf__max_features": [8000],
        "clf__n_estimators": [400],
        "clf__learning_rate": [0.05],
        "clf__num_leaves": [63],
        "clf__max_depth": [10],
        "clf__subsample": [0.8],
        "clf__subsample_freq": [1],
        "clf__reg_lambda": [1.0],
    }
    if fast:
        return {**base, "preprocess__url_tfidf__min_df": [5],
                "clf__colsample_bytree": [0.5], "clf__min_child_samples": [50, 100]}
    return {**base, "preprocess__url_tfidf__min_df": [5, 10],
            "clf__colsample_bytree": [0.3, 0.5], "clf__min_child_samples": [50, 100]}


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
    print("EVALUATION RESULTS (family-disjoint out-of-fold)")
    print("=" * 60)

    print("\n--- Confusion Matrix (default threshold=0.5, original labels) ---")
    print(confusion_matrix(y_test, y_pred_default))

    print("\n--- Classification Report (default threshold=0.5) ---")
    print(classification_report(y_test, y_pred_default, digits=4))

    print(f"\n--- FP-capped threshold (from out-of-fold predictions) for "
          f"malicious label={malicious_label}: {best_threshold:.4f} ---")
    print("Confusion Matrix (tuned threshold, malicious=1):")
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
        help="Use the small param grid (2 combos vs 8).",
    )
    parser.add_argument(
        "--augment",
        action="store_true",
        default=False,
        help=(
            "Add the community Discord scam-domain lists as malicious samples, "
            "balanced by the same number of Tranco top-200k domains as benign."
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

    # ── De-duplicate exact URLs ───────────────────────────────────────────────
    # The same URL landing in both train and test is direct leakage.
    before = len(df)
    df = df.drop_duplicates(subset="url").reset_index(drop=True)
    if len(df) < before:
        logger.info("Dropped %d duplicate URL rows (%d → %d)", before - len(df), before, len(df))

    malicious_label = int(os.getenv("AI_MALICIOUS_LABEL", "0"))
    orig_urls = set(df["url"].astype(str).str.strip())
    if args.augment:
        df = (
            pd.concat([df[["url", "label"]], _augmentation_rows(malicious_label)], ignore_index=True)
            .drop_duplicates(subset="url").reset_index(drop=True)
        )
        logger.info("With augmentation: %d rows", len(df))

    # ── Feature extraction ────────────────────────────────────────────────────
    logger.info("Extracting features (include_page=%s) …", include_page)
    X, y = _extract_features_parallel(df, include_page=include_page)

    # Real-world path URLs and bare augmentation domains get equal total weight,
    # so ~80k bare domains can't drown out the ~9k URLs the bot actually sees.
    is_orig = X["url"].isin(orig_urls).to_numpy()
    weights = np.where(is_orig, max((~is_orig).sum() / max(is_orig.sum(), 1), 1.0), 1.0)

    feature_version = _get_feature_version(X.iloc[0].to_dict())
    logger.info("Feature set: %d columns | version: %s", len(X.columns), feature_version)

    # ── Group-aware, leakage-free evaluation ──────────────────────────────────
    # The URL string feeds a char-level TF-IDF, so the model can memorise a
    # hostname. To measure real performance on brand-new domains we group by
    # domain *family* (see _family) and use group-aware CV everywhere — every
    # score below reflects domain families the model has NEVER seen in training.
    # A single held-out fold is high-variance here (a few giant families dominate
    # it), so we report pooled 5-fold out-of-fold predictions instead.
    groups = X["url"].map(_family)
    g_arr = groups.to_numpy()

    numeric_features = [col for col in X.columns if col != "url"]
    pipeline = _build_pipeline(numeric_features)
    logger.info("Rows: %d | unique domain families: %d", len(X), groups.nunique())

    # ── Hyperparameter search (group-aware CV) ────────────────────────────────
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
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
    search.fit(X, y, groups=g_arr, clf__sample_weight=weights)
    best_model = search.best_estimator_          # refit on ALL rows by GridSearchCV
    logger.info("Best group-CV F1 : %.4f", search.best_score_)
    logger.info("Best params: %s", search.best_params_)

    classes = list(best_model.classes_)
    mal_idx = (
        classes.index(malicious_label) if malicious_label in classes
        else (1 if len(classes) > 1 else 0)
    )
    other_label = next((c for c in classes if c != malicious_label), malicious_label)

    # ── Honest metrics + threshold from out-of-fold predictions ───────────────
    # Each out-of-fold probability comes from a model that never saw that row's
    # domain, so these numbers estimate real performance on new domains — and the
    # threshold is tuned here, never on a held-out test set.
    logger.info("Computing domain-disjoint out-of-fold predictions …")
    # Run the folds sequentially (n_jobs=1): LightGBM already parallelises each
    # fit across all cores, so parallelising folds too oversubscribes the CPU and
    # can crash a worker on deep 400-tree models.
    oof_prob = cross_val_predict(
        best_model, X, y, cv=cv, groups=g_arr,
        method="predict_proba", n_jobs=1, params={"clf__sample_weight": weights},
    )[:, mal_idx]

    y_true_binary = (y == malicious_label).astype(int)
    # Threshold: the lowest cut-off whose out-of-fold false-positive rate stays
    # <= FP_TARGET on benign real-world URLs *and* benign bare domains. A false
    # positive here means banning an innocent member, so this beats max-F1.
    benign = (y != malicious_label).to_numpy()
    def fp_at(t):
        return max((oof_prob[benign & m] >= t).mean() for m in (is_orig, ~is_orig) if (benign & m).any())
    ok = [t for t in np.linspace(0.05, 0.99, 95) if fp_at(t) <= FP_TARGET]
    best_threshold = float(min(ok)) if ok else 0.99
    y_pred_opt = (oof_prob >= best_threshold).astype(int)
    logger.info("Threshold %.2f keeps OOF false positives <= %.0f%% (worst group: %.2f%%)",
                best_threshold, FP_TARGET * 100, fp_at(best_threshold) * 100)
    y_pred_default = np.where(oof_prob >= 0.5, malicious_label, other_label)

    _print_evaluation(
        y_test=y,
        y_pred_default=y_pred_default,
        y_true_binary=y_true_binary,
        y_pred_opt=y_pred_opt,
        y_prob=oof_prob,
        malicious_label=malicious_label,
        best_threshold=best_threshold,
    )
    oof_metrics = {
        "roc_auc": round(float(roc_auc_score(y_true_binary, oof_prob)), 6),
        "pr_auc": round(float(average_precision_score(y_true_binary, oof_prob)), 6),
        "f1_at_threshold": round(float(f1_score(y_true_binary, y_pred_opt)), 6),
    }

    # ── Save model ────────────────────────────────────────────────────────────
    # best_model is already refit on every row (GridSearchCV refit=True), so no
    # data is wasted; the OOF threshold above is kept for deployment.
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
            "eval": "5-fold StratifiedGroupKFold by domain family (family-disjoint OOF)",
            "threshold_rule": f"lowest t with OOF FP <= {FP_TARGET:.0%} on benign URLs and bare domains",
            "augmented": args.augment,
            "oof_metrics": oof_metrics,
        },
    }
    joblib.dump(payload, args.output)
    logger.info(
        "Model saved → %s  (threshold=%.4f | OOF ROC-AUC=%.4f PR-AUC=%.4f F1=%.4f)",
        args.output, best_threshold,
        oof_metrics["roc_auc"], oof_metrics["pr_auc"], oof_metrics["f1_at_threshold"],
    )

    # ── Quick sanity check ────────────────────────────────────────────────────
    test_url = "http://vip-zone2026.site/login"
    test_feats = extract_features(test_url)
    test_feats["url"] = test_url
    test_df = pd.DataFrame([test_feats])
    prob = float(best_model.predict_proba(test_df)[0, mal_idx])
    logger.info("Sanity check | %s → malicious probability: %.4f", test_url, prob)


if __name__ == "__main__":
    main()