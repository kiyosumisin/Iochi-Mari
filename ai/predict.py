"""
predict.py
----------
URL malicious classifier — inference + SHAP explainability.

Public API
----------
load_model()          -> sklearn Pipeline (cached singleton)
predict_url(url, ...) -> PredictionResult
"""

from __future__ import annotations

import os
import logging
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Suppress sklearn's "X does not have valid feature names" warning that fires
# inside SHAP's TreeExplainer when it probes the LightGBM booster internally.
# Our predict_url() already passes a named DataFrame to shap_values(); this
# warning comes from sklearn validation inside SHAP that we cannot control.
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
    module="sklearn",
)
warnings.filterwarnings(
    "ignore",
    message="LightGBM binary classifier with TreeExplainer shap values output has changed",
    category=UserWarning,
    module="shap",
)

import joblib
import numpy as np
import pandas as pd

from ai.feature_extractor import extract_features

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons (loaded once, reused across requests)
# ---------------------------------------------------------------------------
_MODEL = None
_EXPLAINER = None          # shap.LinearExplainer (built lazily after model load)
_FEATURE_NAMES: list[str] = []
_META: dict = {}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class FeatureContribution:
    """A single feature's SHAP contribution toward the malicious class."""
    feature: str
    value: float        # raw feature value fed to the model
    shap_value: float   # contribution toward P(malicious); positive = more malicious


@dataclass
class PredictionResult:
    probability: float
    is_malicious: bool
    threshold: float
    top_features: list[FeatureContribution] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _get_model_path() -> Path:
    env_path = os.getenv("AI_MODEL_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return Path(__file__).resolve().parent / "model.pkl"


def _get_feature_version() -> str:
    """Fingerprint the current feature extractor by its output key names."""
    sample = extract_features("http://example.com")
    return ",".join(sorted(k for k in sample if k != "url"))


def _build_feature_names(pipeline) -> list[str]:
    """
    Reconstruct the full ordered feature name list from the fitted
    ColumnTransformer so SHAP values can be labelled correctly.

    Order mirrors ColumnTransformer output:
      [tfidf_<char_ngram> x N, url_length, path_length, ..., is_ip_address]
    """
    ct = pipeline.named_steps["preprocess"]
    names: list[str] = []

    for transformer_name, transformer, _ in ct.transformers_:
        if transformer in ("drop", "passthrough"):
            continue
        if hasattr(transformer, "get_feature_names_out"):
            names.extend(
                f"tfidf_{n}" if transformer_name == "url_tfidf" else n
                for n in transformer.get_feature_names_out()
            )
        elif hasattr(transformer, "feature_names_in_"):
            names.extend(transformer.feature_names_in_.tolist())

    return names


def _build_explainer(pipeline) -> Optional[object]:
    """
    Build the appropriate SHAP explainer for the classifier in the pipeline.

    - LogisticRegression  → shap.LinearExplainer  (exact, fast)
    - LGBMClassifier      → shap.TreeExplainer    (exact, fast)
    - anything else       → None (explainability disabled gracefully)
    """
    try:
        import shap
    except Exception as exc:
        logger.warning("shap unavailable — explainability disabled: %s", exc)
        return None

    clf = pipeline.named_steps.get("clf")
    if clf is None:
        logger.warning("No 'clf' step found in pipeline — explainer skipped.")
        return None

    clf_type = type(clf).__name__

    # ── LightGBM ──────────────────────────────────────────────────────────────
    if clf_type == "LGBMClassifier":
        try:
            explainer = shap.TreeExplainer(clf)
            logger.info("SHAP TreeExplainer initialised for LGBMClassifier.")
            return explainer
        except Exception as exc:
            logger.warning("SHAP TreeExplainer init failed: %s", exc)
            return None

    # ── Logistic Regression (linear fallback) ─────────────────────────────────
    if hasattr(clf, "coef_"):
        try:
            explainer = shap.LinearExplainer(
                clf,
                masker=shap.maskers.Independent(
                    data=np.zeros((1, clf.coef_.shape[1]))
                ),
            )
            logger.info(
                "SHAP LinearExplainer initialised (%d features).", clf.coef_.shape[1]
            )
            return explainer
        except Exception as exc:
            logger.warning("SHAP LinearExplainer init failed: %s", exc)
            return None

    logger.warning("Unsupported classifier type '%s' — explainer skipped.", clf_type)
    return None


# ---------------------------------------------------------------------------
# Public: load model
# ---------------------------------------------------------------------------
def load_model():
    """Load (and cache) the model pipeline from disk."""
    global _MODEL, _EXPLAINER, _FEATURE_NAMES, _META

    if _MODEL is not None:
        return _MODEL

    model_path = _get_model_path()
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    payload = joblib.load(model_path)
    if isinstance(payload, dict) and "model" in payload:
        _MODEL = payload["model"]
        _META = payload.get("meta", {}) or {}
    else:
        _MODEL = payload
        _META = {}

    # Feature version guard
    saved_version = _META.get("feature_version")
    current_version = _get_feature_version()
    if saved_version and saved_version != current_version:
        logger.warning(
            "Feature version mismatch: model trained with '%s', current is '%s'. "
            "Retrain recommended.",
            saved_version,
            current_version,
        )

    # Build SHAP artefacts once, at startup.
    # SHAP drags in heavy deps (shap -> IPython) that the bot never uses — it
    # only reads probability/is_malicious, not the SHAP explanation. So building
    # the explainer is opt-in via AI_ENABLE_SHAP. This keeps the first prediction
    # fast and avoids crashing if the shap/IPython import chain is broken/slow on
    # the host. (app.py can set AI_ENABLE_SHAP=true to get /predict explanations.)
    _FEATURE_NAMES = _build_feature_names(_MODEL)
    if os.getenv("AI_ENABLE_SHAP", "false").lower() in ("1", "true", "yes"):
        _EXPLAINER = _build_explainer(_MODEL)
    else:
        _EXPLAINER = None

    return _MODEL


# ---------------------------------------------------------------------------
# Public: predict
# ---------------------------------------------------------------------------
def predict_url(
    url: str,
    threshold: Optional[float] = None,
    include_page: Optional[bool] = None,
    top_n: int = 3,
) -> PredictionResult:
    """
    Classify a URL as malicious or benign.

    Args:
        url          : URL string to classify.
        threshold    : Decision threshold — overrides env var and model default.
        include_page : Fetch live page content for extra features.
                       Defaults to the mode used at training time.
        top_n        : Number of top SHAP contributors to return.

    Threshold priority:
        1. ``threshold`` argument
        2. ``AI_THRESHOLD`` environment variable
        3. ``best_threshold`` saved in model.pkl
        4. Hard default 0.5

    Returns:
        PredictionResult with probability, verdict, threshold, and top features.
    """
    if not url or not isinstance(url, str):
        raise ValueError(f"Invalid URL: {url!r}")

    model = load_model()

    # Resolve include_page from meta if not specified
    if include_page is None:
        include_page = bool(_META.get("include_page", False))

    # Build feature row
    feats = extract_features(url, include_page=include_page)
    feats["url"] = url
    df = pd.DataFrame([feats])

    # --- Probability ---
    proba = model.predict_proba(df)[0]
    classes: list = list(getattr(model, "classes_", []))
    malicious_label = int(os.getenv("AI_MALICIOUS_LABEL", _META.get("malicious_label", 0)))
    mal_idx = (
        classes.index(malicious_label)
        if malicious_label in classes
        else (1 if len(proba) > 1 else 0)
    )
    prob = float(proba[mal_idx])

    # --- Threshold resolution (priority order) ---
    if threshold is not None:
        th = float(threshold)
    elif "AI_THRESHOLD" in os.environ:
        th = float(os.environ["AI_THRESHOLD"])
    elif "best_threshold" in _META:
        th = float(_META["best_threshold"])
    else:
        th = 0.5

    # --- SHAP explanation ---
    top_features: list[FeatureContribution] = []

    if _EXPLAINER is not None and _FEATURE_NAMES:
        try:
            X_transformed = model.named_steps["preprocess"].transform(df)

            # Both LinearExplainer and TreeExplainer need a dense 2-D array.
            X_dense = (
                X_transformed.toarray()
                if hasattr(X_transformed, "toarray")
                else np.asarray(X_transformed)
            )

            clf = model.named_steps["clf"]
            clf_type = type(clf).__name__

            if clf_type == "LGBMClassifier":
                # LightGBM's feature_name() returns the exact names it was trained with
                # (the full ColumnTransformer output: tfidf cols + numeric cols).
                # Passing a DataFrame with those names silences the feature-name warning.
                lgbm_feature_names: list[str] = clf.feature_name_
                if len(lgbm_feature_names) == X_dense.shape[1]:
                    X_named = pd.DataFrame(X_dense, columns=lgbm_feature_names)
                else:
                    # Fallback: truncate/pad to match — avoids shape mismatch crash
                    X_named = pd.DataFrame(
                        X_dense,
                        columns=lgbm_feature_names[: X_dense.shape[1]],
                    )
                shap_values = _EXPLAINER.shap_values(X_named)

                # Binary LGBM TreeExplainer output: (n_samples, n_features)
                sv = np.asarray(shap_values)
                if sv.ndim == 3:
                    sv = sv[mal_idx][0]
                elif sv.ndim == 2:
                    sv = sv[0]
            else:
                # LinearExplainer path (Logistic Regression)
                shap_values = _EXPLAINER.shap_values(X_dense)
                sv = np.asarray(shap_values)
                if sv.ndim == 3:
                    sv = sv[mal_idx][0]
                elif sv.ndim == 2:
                    sv = sv[0]

            # Collect numeric column names for raw-value look-up
            numeric_cols: list[str] = [
                col
                for _, _, cols in model.named_steps["preprocess"].transformers_
                if isinstance(cols, list)
                for col in cols
            ]

            ranked_idx = np.argsort(np.abs(sv))[::-1][:top_n]
            for i in ranked_idx:
                fname = _FEATURE_NAMES[i] if i < len(_FEATURE_NAMES) else f"feature_{i}"
                raw_val = (
                    float(df[fname].iloc[0])
                    if fname in numeric_cols and fname in df.columns
                    else float(X_dense[0, i])
                )
                top_features.append(
                    FeatureContribution(
                        feature=fname,
                        value=round(raw_val, 6),
                        shap_value=round(float(sv[i]), 6),
                    )
                )
        except Exception as exc:
            logger.warning("SHAP explanation failed for '%s': %s", url, exc)


    return PredictionResult(
        probability=round(prob, 6),
        is_malicious=prob >= th,
        threshold=round(th, 6),
        top_features=top_features,
    )