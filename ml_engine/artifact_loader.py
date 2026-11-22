"""
Artifact Loader for AegisFlow-OmniSOC PyTorch Inference Engine.
Automatically downloads and extracts GITHUB_ARTIFACTS_ZIP_URL into ./artifacts_cache/
and loads all certified `best_aegisflow_v6_*.pt` + `soc_deployment_bundle_*.pkl` profiles.
"""

from __future__ import annotations

import os
import pickle
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict

import torch

from model_arch import AegisFlowZenithV8, TailPreservingDualScaler

# Register TailPreservingDualScaler on __main__ so notebooks pickled from __main__ unpickle cleanly
setattr(sys.modules["__main__"], "TailPreservingDualScaler", TailPreservingDualScaler)


class ArtifactRegistry:
    def __init__(self, cache_dir: str = "./artifacts_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.profiles: Dict[str, Dict[str, Any]] = {}

    def download_and_extract_if_configured(self) -> None:
        zip_url = os.environ.get("GITHUB_ARTIFACTS_ZIP_URL", "").strip()
        local_zip = Path("../AegisFlow_V8.1_Zenith.zip")

        if zip_url and not any(self.cache_dir.rglob("*.pt")):
            target_zip = self.cache_dir / "aegisflow_artifacts.zip"
            print(f"[ml_engine] Downloading artifacts from {zip_url} ...")
            urllib.request.urlretrieve(zip_url, target_zip)
            with zipfile.ZipFile(target_zip, "r") as zf:
                zf.extractall(self.cache_dir)
            print(f"[ml_engine] Extracted artifacts into {self.cache_dir}")
        elif local_zip.exists() and local_zip.stat().st_size > 1024 * 1024 and not any(self.cache_dir.rglob("*.pt")):
            print(f"[ml_engine] Extracting local {local_zip} ...")
            with zipfile.ZipFile(local_zip, "r") as zf:
                zf.extractall(self.cache_dir)

    def load_all_profiles(self) -> Dict[str, Dict[str, Any]]:
        self.download_and_extract_if_configured()

        for pkl_path in sorted(self.cache_dir.rglob("soc_deployment_bundle_*.pkl")):
            ds_name = pkl_path.stem.replace("soc_deployment_bundle_", "")
            pt_candidates = list(self.cache_dir.rglob(f"best_aegisflow_v6_{ds_name}.pt"))
            if not pt_candidates:
                continue

            with open(pkl_path, "rb") as f:
                bundle = pickle.load(f)

            in_features = len(bundle["feature_names"])
            num_known = len(bundle["known_classes"])
            use_qt = bool(bundle.get("use_qt", True))

            model = AegisFlowZenithV8(
                in_features=in_features,
                num_known_classes=num_known,
                use_qt=use_qt,
            ).to(self.device)
            state_dict = torch.load(pt_candidates[0], map_location=self.device, weights_only=True)
            model.load_state_dict(state_dict, strict=True)
            model.eval()

            self.profiles[ds_name] = {
                "dataset_name": ds_name,
                "model": model,
                "bundle": bundle,
                "raw_feature_names": bundle["raw_feature_names"],
                "feature_names": bundle["feature_names"],
                "known_classes": bundle["known_classes"],
                "zero_day_classes": bundle.get("zero_day_classes", []),
                "use_qt": use_qt,
                "scaler": bundle["scaler"],
                "calibration": bundle["calibration"],
                "metrics_summary": bundle.get("metrics_summary", {}),
            }
            print(f"[ml_engine] Loaded certified v8.1 profile: {ds_name} ({len(bundle['raw_feature_names'])} raw feats)")

        return self.profiles
