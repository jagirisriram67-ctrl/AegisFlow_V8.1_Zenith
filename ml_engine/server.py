"""
AegisFlow-OmniSOC Companion PyTorch FastAPI Inference Server.
Exposes POST /infer, POST /explain, GET /profiles, and GET /health.
Links seamlessly to the Node.js AegisFlow-OmniSOC server via PYTORCH_ENGINE_URL.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from artifact_loader import ArtifactRegistry
from model_arch import compute_class_locked_ig_shap_and_lime, evaluate_single_or_batch

app = FastAPI(
    title="AegisFlow-Zenith v8.1 PyTorch Inference Engine",
    version="8.1.0",
)

registry = ArtifactRegistry(cache_dir=os.environ.get("ARTIFACTS_CACHE_DIR", "./artifacts_cache"))


class InferRequest(BaseModel):
    profile: str = Field(..., description="Dataset profile e.g. NF-BoT-IoT-v2, N-BaIoT, CIC-IoT-2023-34Class")
    features: Dict[str, float] = Field(..., description="Raw feature dictionary (40, 46, or 115 features)")


class ExplainRequest(BaseModel):
    profile: str
    features: Dict[str, float]
    target_class: Optional[int] = None


@app.on_event("startup")
def startup_load() -> None:
    registry.load_all_profiles()


def _vectorize_raw_features(profile_obj: Dict[str, Any], features: Dict[str, float]) -> np.ndarray:
    raw_names: List[str] = profile_obj["raw_feature_names"]
    vec = np.zeros((1, len(raw_names)), dtype=np.float32)
    for i, col in enumerate(raw_names):
        val = features.get(col, 0.0)
        try:
            fval = float(val)
            if not np.isfinite(fval):
                fval = 0.0
        except (TypeError, ValueError):
            fval = 0.0
        vec[0, i] = fval
    return profile_obj["scaler"].transform(vec)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "device": str(registry.device),
        "loaded_profiles": list(registry.profiles.keys()),
        "engine": "AegisFlow-Zenith v8.1 PyTorch",
    }


@app.get("/profiles")
def list_profiles() -> Dict[str, Any]:
    return {
        "profiles": [
            {
                "id": p["dataset_name"],
                "raw_feature_count": len(p["raw_feature_names"]),
                "known_classes": p["known_classes"],
                "zero_day_classes": p["zero_day_classes"],
                "metrics_summary": p["metrics_summary"],
            }
            for p in registry.profiles.values()
        ]
    }


@app.post("/infer")
def infer(req: InferRequest) -> Dict[str, Any]:
    if req.profile not in registry.profiles:
        raise HTTPException(
            status_code=404,
            detail=f"Profile '{req.profile}' not loaded. Available: {list(registry.profiles.keys())}",
        )
    t0 = time.perf_counter()
    p = registry.profiles[req.profile]
    x_scaled = _vectorize_raw_features(p, req.features)
    res = evaluate_single_or_batch(p["model"], x_scaled, p["calibration"], registry.device)
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    idx = int(res["closed_choice"][0])
    known_classes = p["known_classes"]
    probs = res["probs"][0].tolist()
    prob_map = {known_classes[i]: round(float(probs[i]), 5) for i in range(len(known_classes))}
    prims = {k: round(float(v[0]), 4) for k, v in res["primitives"].items()}

    return {
        "profile": req.profile,
        "engine": "LIVE_PYTORCH_BRIDGE",
        "latency_ms": latency_ms,
        "closed_class_index": idx,
        "closed_set_nearest_class": known_classes[idx],
        "confidence": round(float(max(probs)), 5),
        "probabilities": prob_map,
        "shannon_entropy": round(float(res["shannon_entropy"][0]), 5),
        "epistemic_jsd": round(float(res["epistemic_jsd"][0]), 5),
        "epistemic_latvar": round(float(res["epistemic_latvar"][0]), 5),
        "meta_ood_score": round(float(res["meta_score"][0]), 5),
        "tau_amber": round(float(res["tau_amber"][0]), 5),
        "tau_red": round(float(res["tau_red"][0]), 5),
        "ood_primitives": prims,
        "embedding_192d": res["z_joint_192"][0].tolist(),
        "x_canonical": x_scaled[0].tolist(),
    }


@app.post("/explain")
def explain(req: ExplainRequest) -> Dict[str, Any]:
    if req.profile not in registry.profiles:
        raise HTTPException(status_code=404, detail=f"Profile '{req.profile}' not loaded.")
    t0 = time.perf_counter()
    p = registry.profiles[req.profile]
    x_scaled = _vectorize_raw_features(p, req.features)
    eval_res = evaluate_single_or_batch(p["model"], x_scaled, p["calibration"], registry.device)
    target_idx = req.target_class if req.target_class is not None else int(eval_res["closed_choice"][0])
    top5 = compute_class_locked_ig_shap_and_lime(
        p["model"],
        x_scaled[0],
        p["calibration"],
        p["raw_feature_names"],
        p["use_qt"],
        target_idx,
        registry.device,
    )
    return {
        "profile": req.profile,
        "target_class": p["known_classes"][target_idx],
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "top_features": top5,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8001")))
