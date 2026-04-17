import os
import logging
from pathlib import Path

import joblib
import pandas as pd

from ai.feature_extractor import extract_features

logger = logging.getLogger(__name__)

_MODEL = None
_META = {}


def _get_model_path() -> Path:
    env_path = os.getenv("AI_MODEL_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return Path(__file__).resolve().parent / "model.pkl"


def load_model():
    global _MODEL, _META
    if _MODEL is not None:
        return _MODEL

    model_path = _get_model_path()
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    payload = joblib.load(model_path)
    if isinstance(payload, dict) and "model" in payload:
        _MODEL = payload["model"]
        _META = payload.get("meta", {}) if isinstance(payload.get("meta", {}), dict) else {}
    else:
        _MODEL = payload
        _META = {}

    # Cảnh báo nếu feature version không khớp
    saved_version = _META.get("feature_version")
    current_version = _get_feature_version()
    if saved_version and saved_version != current_version:
        logger.warning(
            f"Feature version mismatch: model trained with '{saved_version}', "
            f"current extractor is '{current_version}'. Retrain recommended."
        )

    return _MODEL


def _get_feature_version() -> str:
    """Version đơn giản dựa trên tên các feature được extract."""
    from ai.feature_extractor import extract_features as ef
    sample = ef("http://example.com")
    return ",".join(sorted(k for k in sample if k != "url"))


def predict_url(url: str, threshold: float | None = None, include_page: bool | None = None):
    """
    Returns (probability, is_malicious).
 
    Args:
        url          : URL to classify.
        threshold    : Decision threshold (overrides env var and model default).
        include_page : If True, fetch the page and include HTML content features.
                       If None (default), auto-detect from the model's saved meta.
 
    Threshold priority order:
      1. `threshold` argument passed directly
      2. AI_THRESHOLD environment variable
      3. best_threshold saved in model.pkl at training time
      4. Default 0.5
    """
    if not url or not isinstance(url, str):
        raise ValueError(f"URL không hợp lệ: {url!r}")

    model = load_model()

    # Nếu không chỉ định, dùng mode đã train
    if include_page is None:
        include_page = bool(_META.get("include_page", False))

    feats = extract_features(url, include_page=include_page)
    feats["url"] = url
    df = pd.DataFrame([feats])

    proba = model.predict_proba(df)[0]
    classes = list(getattr(model, "classes_", []))
    malicious_label = int(os.getenv("AI_MALICIOUS_LABEL", _META.get("malicious_label", 0)))

    if malicious_label in classes:
        idx = classes.index(malicious_label)
    else:
        idx = 1 if len(proba) > 1 else 0

    prob = float(proba[idx])

    # Xác định ngưỡng theo thứ tự ưu tiên
    if threshold is not None:
        th = threshold
    elif "AI_THRESHOLD" in os.environ:
        th = float(os.environ["AI_THRESHOLD"])
    elif "best_threshold" in _META:
        th = float(_META["best_threshold"])
    else:
        th = 0.5

    return prob, prob >= th