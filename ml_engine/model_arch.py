"""
AegisFlow-Zenith v8.1 Exact PyTorch Architecture & 9-Primitive Fisher-Probit MetaOOD.
Matches `best_aegisflow_v6_*.pt` and `soc_deployment_bundle_*.pkl` state_dicts byte-for-byte.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from scipy.special import ndtri
from sklearn.preprocessing import QuantileTransformer, StandardScaler


BASE_LEAKAGE_COLS = {
    "id", "pkSeqID", "seq", "subcategory", "saddr", "daddr", "srcip", "dstip",
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "sport",
    "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS",
    "stime", "ltime", "Timestamp", "Flow ID", "Label", "label", "attack_cat",
}

SHORTCUT_HEADER_COLS = {
    "L4_DST_PORT", "dport", "MIN_TTL", "MAX_TTL", "sttl", "dttl",
    "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
}


class TailPreservingDualScaler:
    """Exact pickle-compatible TailPreservingDualScaler from AegisFlow-Zenith v8.1."""

    def __init__(self, use_quantile_twin: bool = True):
        self.use_quantile_twin = use_quantile_twin
        self.heavy_tail_mask: Optional[np.ndarray] = None
        self.std_scaler = StandardScaler()
        self.qt_scaler = QuantileTransformer(
            n_quantiles=1500,
            output_distribution="normal",
            subsample=75000,
            random_state=42,
        )

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float32)
        spans = np.ptp(X, axis=0)
        self.heavy_tail_mask = spans > 500.0
        X_proc = X.copy()
        if np.any(self.heavy_tail_mask):
            ht = X_proc[:, self.heavy_tail_mask]
            X_proc[:, self.heavy_tail_mask] = np.sign(ht) * np.log1p(np.abs(ht))
        X_std = self.std_scaler.fit_transform(X_proc).astype(np.float32)
        if not self.use_quantile_twin:
            return X_std
        X_qt = self.qt_scaler.fit_transform(X).astype(np.float32)
        return np.hstack([X_std, X_qt])

    def transform(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float32)
        X_proc = X.copy()
        if self.heavy_tail_mask is not None and np.any(self.heavy_tail_mask):
            ht = X_proc[:, self.heavy_tail_mask]
            X_proc[:, self.heavy_tail_mask] = np.sign(ht) * np.log1p(np.abs(ht))
        X_std = self.std_scaler.transform(X_proc).astype(np.float32)
        if not self.use_quantile_twin:
            return X_std
        X_qt = self.qt_scaler.transform(X).astype(np.float32)
        return np.hstack([X_std, X_qt])


class ContextualLearnableFeatureGate(nn.Module):
    """Lipschitz-bounded Context-modulated Learnable Feature Gating (LFG)."""

    def __init__(self, in_features: int, context_dim: int = 64):
        super().__init__()
        self.pointwise_weight = nn.Parameter(torch.ones(in_features))
        self.pointwise_bias = nn.Parameter(torch.zeros(in_features))
        self.context_net = nn.Sequential(
            nn.Linear(in_features, context_dim),
            nn.LayerNorm(context_dim),
            nn.SiLU(),
            nn.Linear(context_dim, in_features),
        )
        nn.init.xavier_uniform_(self.context_net[0].weight)
        nn.init.xavier_uniform_(self.context_net[3].weight)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        x_smooth = x / (1.0 + 0.05 * torch.abs(x))
        gates = torch.sigmoid(
            x_smooth * self.pointwise_weight + self.pointwise_bias + self.context_net(x_smooth)
        )
        return x * gates, gates


class LowRankCrossNetLayer(nn.Module):
    """DCN-v2 Low-Rank Feature Cross Layer modeling multiplicative telemetry ratios."""

    def __init__(self, in_features: int, rank: int = 32):
        super().__init__()
        r = min(rank, in_features)
        self.v_proj = nn.Linear(in_features, r, bias=False)
        self.u_proj = nn.Linear(r, in_features, bias=True)
        self.norm = nn.LayerNorm(in_features)
        nn.init.xavier_uniform_(self.v_proj.weight, gain=0.5)
        nn.init.xavier_uniform_(self.u_proj.weight, gain=0.5)
        nn.init.zeros_(self.u_proj.bias)

    def forward(self, x0: torch.Tensor) -> torch.Tensor:
        x_damped = torch.tanh(x0 * 0.25) * 4.0
        cross = x_damped * self.u_proj(self.v_proj(x_damped))
        return self.norm(x0 + 0.25 * cross)


class TabMLinear(nn.Module):
    """Parameter-Efficient BatchEnsemble Layer (M=8 rank-1 subnetworks in 1 matmul)."""

    def __init__(
        self,
        in_features: int,
        out_features: int,
        num_members: int = 8,
        r_std: float = 0.20,
    ):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.num_members = num_members
        self.weight = nn.Parameter(torch.empty(out_features, in_features))
        nn.init.kaiming_uniform_(self.weight, a=math.sqrt(5))
        self.r = nn.Parameter(
            torch.ones(num_members, in_features)
            + torch.randn(num_members, in_features) * r_std
        )
        self.s = nn.Parameter(
            torch.ones(num_members, out_features)
            + torch.randn(num_members, out_features) * 0.15
        )
        self.bias = nn.Parameter(
            torch.empty(num_members, out_features).uniform_(-0.02, 0.02)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x_scaled = x * self.r.unsqueeze(0)
        out = F.linear(x_scaled, self.weight)
        return out * self.s.unsqueeze(0) + self.bias.unsqueeze(0)


class PairedPeriodicFeatureTokenizer(nn.Module):
    """Pairs canonical feature j with its quantile twin + bounded Periodic Fourier embeddings."""

    def __init__(
        self,
        in_features: int,
        use_qt: bool = True,
        num_tokens: int = 8,
        d_model: int = 64,
    ):
        super().__init__()
        self.in_features = in_features
        self.use_qt = use_qt
        self.raw_dim = (in_features // 2) if use_qt else in_features
        self.num_tokens = num_tokens
        self.d_model = d_model
        self.freq = nn.Parameter(torch.randn(1, self.raw_dim) * 0.25)
        per_feat_channels = 4 if use_qt else 3
        self.slice_feats = math.ceil(self.raw_dim / num_tokens)
        self.padded_raw_dim = self.slice_feats * num_tokens
        token_in_dim = self.slice_feats * per_feat_channels
        self.group_weights = nn.Parameter(
            torch.randn(num_tokens, token_in_dim, d_model) * 0.04
        )
        self.group_biases = nn.Parameter(torch.zeros(num_tokens, d_model))
        self.cls_token = nn.Parameter(torch.randn(1, 1, d_model) * 0.02)

    def forward(self, x_gated: torch.Tensor) -> torch.Tensor:
        B = x_gated.size(0)
        if self.use_qt:
            x_std = x_gated[:, : self.raw_dim]
            x_qt = x_gated[:, self.raw_dim :]
            ang = torch.clamp(x_std, -8.0, 8.0) * torch.clamp(self.freq, -0.6, 0.6)
            feat_tensor = torch.stack(
                [x_std, x_qt, torch.sin(ang), torch.cos(ang)], dim=-1
            )
        else:
            x_std = x_gated
            ang = torch.clamp(x_std, -8.0, 8.0) * torch.clamp(self.freq, -0.6, 0.6)
            feat_tensor = torch.stack([x_std, torch.sin(ang), torch.cos(ang)], dim=-1)
        if self.raw_dim < self.padded_raw_dim:
            pad = torch.zeros(
                B,
                self.padded_raw_dim - self.raw_dim,
                feat_tensor.size(-1),
                device=x_gated.device,
                dtype=x_gated.dtype,
            )
            feat_tensor = torch.cat([feat_tensor, pad], dim=1)
        groups = feat_tensor.view(B, self.num_tokens, -1)
        tokens = torch.einsum("bti,tid->btd", groups, self.group_weights) + self.group_biases.unsqueeze(0)
        cls_tok = self.cls_token.expand(B, -1, -1)
        return torch.cat([cls_tok, tokens], dim=1)


class SwiGLUMultiHeadSelfAttention(nn.Module):
    """Pre-Norm Multi-Head Self-Attention with SwiGLU Feed-Forward Network."""

    def __init__(self, d_model: int = 64, num_heads: int = 4, dropout: float = 0.10):
        super().__init__()
        assert d_model % num_heads == 0
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_k = d_model // num_heads
        self.q_proj = nn.Linear(d_model, d_model)
        self.k_proj = nn.Linear(d_model, d_model)
        self.v_proj = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)
        self.attn_dropout = nn.Dropout(dropout)
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        hidden_ffn = d_model * 2
        self.w1 = nn.Linear(d_model, hidden_ffn)
        self.w2 = nn.Linear(d_model, hidden_ffn)
        self.w3 = nn.Linear(hidden_ffn, d_model)
        self.ffn_drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        B, S, D = x.shape
        h = self.norm1(x)
        Q = self.q_proj(h).view(B, S, self.num_heads, self.d_k).transpose(1, 2)
        K = self.k_proj(h).view(B, S, self.num_heads, self.d_k).transpose(1, 2)
        V = self.v_proj(h).view(B, S, self.num_heads, self.d_k).transpose(1, 2)
        scores = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.d_k)
        attn_weights = F.softmax(scores, dim=-1)
        context = torch.matmul(self.attn_dropout(attn_weights), V)
        context = context.transpose(1, 2).contiguous().view(B, S, D)
        x = x + self.out_proj(context)
        h2 = self.norm2(x)
        swiglu = self.w1(h2) * F.silu(self.w2(h2))
        x = x + self.ffn_drop(self.w3(swiglu))
        return x, attn_weights


class AegisFlowZenithV8(nn.Module):
    """Exact AegisFlow-Zenith v8.1 state_dict-compatible PyTorch backbone."""

    def __init__(
        self,
        in_features: int,
        num_known_classes: int,
        use_qt: bool = True,
        dropout: float = 0.15,
        num_members: int = 8,
    ):
        super().__init__()
        self.in_features = in_features
        self.num_known_classes = num_known_classes
        self.d_model = 64
        self.M = num_members

        self.input_lfg = ContextualLearnableFeatureGate(in_features, context_dim=64)
        self.cross_net = LowRankCrossNetLayer(in_features, rank=32)

        self.tokenizer = PairedPeriodicFeatureTokenizer(
            in_features, use_qt=use_qt, num_tokens=8, d_model=self.d_model
        )
        self.mhsa1 = SwiGLUMultiHeadSelfAttention(
            d_model=self.d_model, num_heads=4, dropout=0.10
        )
        self.mhsa2 = SwiGLUMultiHeadSelfAttention(
            d_model=self.d_model, num_heads=4, dropout=0.10
        )

        self.tabm_fc1 = TabMLinear(in_features, 320, num_members=self.M, r_std=0.25)
        self.tabm_ln1 = nn.LayerNorm(320)
        self.tabm_drop1 = nn.Dropout(dropout)
        self.tabm_fc2 = TabMLinear(320, 192, num_members=self.M, r_std=0.18)
        self.tabm_ln2 = nn.LayerNorm(192)
        self.tabm_drop2 = nn.Dropout(dropout)
        self.tabm_fc3 = TabMLinear(192, 128, num_members=self.M, r_std=0.15)
        self.tabm_ln3 = nn.LayerNorm(128)
        self.input_skip = nn.Linear(in_features, 128)

        self.penultimate_fusion = nn.Sequential(
            nn.Linear(self.d_model * 2 + 128, 128),
            nn.LayerNorm(128),
            nn.SiLU(),
        )
        self.latent_gate = nn.Sequential(
            nn.Linear(128, 128),
            nn.Sigmoid(),
        )

        self.fc_out = TabMLinear(128, num_known_classes, num_members=self.M, r_std=0.12)
        self.supcon_proj = nn.Linear(128, 64, bias=False)
        init_protos = F.normalize(torch.randn(num_known_classes, 64), p=2, dim=-1)
        self.class_prototypes = nn.Parameter(init_protos)

        self.class_embeddings = nn.Embedding(num_known_classes, 32)
        self.decoder = nn.Sequential(
            nn.Linear(128 + 32, 192),
            nn.LayerNorm(192),
            nn.SiLU(),
            nn.Linear(192, 192),
            nn.LayerNorm(192),
            nn.SiLU(),
            nn.Linear(192, in_features),
        )

    def forward(
        self, x: torch.Tensor, cond_labels: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        x_gated, input_gates = self.input_lfg(x)
        x_cross = self.cross_net(x_gated)

        tokens = self.tokenizer(x_cross)
        attn1, _ = self.mhsa1(tokens)
        attn2, attn_weights = self.mhsa2(attn1)
        cls_rep = attn2[:, 0, :]
        mean_rep = attn2[:, 1:, :].mean(dim=1)
        attn_cat = torch.cat([cls_rep, mean_rep], dim=-1).unsqueeze(1).expand(-1, self.M, -1)

        h = x_cross.unsqueeze(1).expand(-1, self.M, -1)
        h = self.tabm_drop1(F.silu(self.tabm_ln1(self.tabm_fc1(h))))
        h = self.tabm_drop2(F.silu(self.tabm_ln2(self.tabm_fc2(h))))
        h = F.silu(self.tabm_ln3(self.tabm_fc3(h))) + 0.25 * self.input_skip(x_cross).unsqueeze(1)

        z_pre_ens = self.penultimate_fusion(torch.cat([attn_cat, h], dim=-1))
        z_ens = z_pre_ens * self.latent_gate(z_pre_ens)
        z = z_ens.mean(dim=1)

        logits_ens = self.fc_out(z_ens)
        logits = logits_ens.mean(dim=1)

        probs_ens = F.softmax(logits_ens.float(), dim=-1)
        mean_probs = probs_ens.mean(dim=1)
        ent_mean = -torch.sum(mean_probs * torch.log(mean_probs.clamp(min=1e-8)), dim=-1)
        mean_ent = -torch.sum(probs_ens * torch.log(probs_ens.clamp(min=1e-8)), dim=-1).mean(dim=1)
        epistemic_jsd = torch.clamp(ent_mean - mean_ent, min=0.0)
        epistemic_latvar = torch.mean(
            torch.sum((z_ens.float() - z.float().unsqueeze(1)) ** 2, dim=-1), dim=1
        )
        z_hyp = F.normalize(self.supcon_proj(z), p=2, dim=-1)
        z_dec = z.detach()
        if cond_labels is None:
            cond_labels = logits.argmax(dim=-1)
        c_emb = self.class_embeddings(cond_labels)
        x_recon_cond = self.decoder(torch.cat([z_dec, c_emb], dim=-1))

        return {
            "logits": logits,
            "logits_ens": logits_ens,
            "z": z,
            "z_ens": z_ens,
            "z_hyp": z_hyp,
            "epistemic_jsd": epistemic_jsd,
            "epistemic_latvar": epistemic_latvar,
            "x_recon_cond": x_recon_cond,
            "input_gates": input_gates,
            "attn_weights": attn_weights,
        }


AegisFlowFoundationV6 = AegisFlowZenithV8


def transform_probit_survival_score(
    vals: np.ndarray,
    closed_choice: np.ndarray,
    cal_sorted_q: np.ndarray,
    cal_q98: np.ndarray,
    cal_iqr: np.ndarray,
) -> np.ndarray:
    """One-sided Gaussian Probit Survival Transformation over 2,000 calibration quantiles."""
    out = np.zeros(len(vals), dtype=np.float32)
    n_q = cal_sorted_q.shape[1]
    for k in range(cal_sorted_q.shape[0]):
        mask = closed_choice == k
        if not np.any(mask):
            continue
        vk = vals[mask]
        qk = cal_sorted_q[k]
        ranks = np.searchsorted(qk, vk, side="right").astype(np.float64)
        u = np.clip((ranks + 0.5) / (n_q + 1.0), 1e-6, 1.0 - 1e-6)
        z_probit = np.maximum(ndtri(u), 0.0)
        tail_excess = np.maximum(vk - cal_q98[k], 0.0) / max(float(cal_iqr[k]), 1e-6)
        out[mask] = (z_probit + 0.45 * np.log1p(tail_excess)).astype(np.float32)
    return out


def compute_synergistic_meta_score(
    norm_prims: np.ndarray, meta_weights: np.ndarray
) -> np.ndarray:
    """Computes the 9-primitive Fisher-Probit MetaOOD evidence score."""
    w = np.asarray(meta_weights, dtype=np.float32).reshape(-1, 1)
    linear = np.sum(norm_prims[: len(w)] * w, axis=0)
    top2 = np.sort(norm_prims[: len(w)], axis=0)[-2:]
    synergy = 0.25 * np.mean(top2, axis=0)
    return (linear + synergy).astype(np.float32)


@torch.no_grad()
def evaluate_single_or_batch(
    model: AegisFlowZenithV8,
    X_scaled: np.ndarray,
    calibration: Dict[str, Any],
    device: torch.device,
) -> Dict[str, Any]:
    """Runs full AegisFlow-Zenith v8.1 forward + 9-primitive Fisher-Probit MetaOOD."""
    model.eval()
    X_np = np.asarray(X_scaled, dtype=np.float32)
    if X_np.ndim == 1:
        X_np = X_np.reshape(1, -1)

    bx = torch.from_numpy(np.ascontiguousarray(X_np)).to(device)
    T_cal = float(calibration["T_cal"])
    bias_gpu = torch.tensor(calibration["class_bias"], dtype=torch.float32, device=device).unsqueeze(0)
    knn_bank_gpu = torch.tensor(calibration["knn_bank"], dtype=torch.float32, device=device)

    in_features = X_np.shape[1]
    shortcut_mask = (
        np.asarray(calibration["shortcut_mask"], dtype=bool)
        if "shortcut_mask" in calibration
        else np.zeros(in_features, dtype=bool)
    )
    behav_col_factor = (~shortcut_mask).astype(np.float32).reshape(1, -1)
    if not np.any(behav_col_factor):
        behav_col_factor = np.ones((1, in_features), dtype=np.float32)
    behav_factor_gpu = torch.tensor(behav_col_factor, dtype=torch.float32, device=device)

    out = model(bx)
    raw_l = out["logits"]
    sc_l = (raw_l / T_cal) + bias_gpu
    pred_y = sc_l.argmax(dim=-1)
    out_rec = model(bx, cond_labels=pred_y)
    rec = torch.mean(((bx - out_rec["x_recon_cond"]) * behav_factor_gpu) ** 2, dim=-1)
    rec_per_feat = ((bx - out_rec["x_recon_cond"]) ** 2).cpu().numpy()

    z_b = out["z"]
    z_norm_b = F.normalize(z_b, p=2, dim=-1)
    z_hyp_b = out["z_hyp"]
    z_joint_192 = F.normalize(torch.cat([z_norm_b, z_hyp_b], dim=-1), p=2, dim=-1)

    has_x_knn = "x_knn_bank" in calibration
    if has_x_knn:
        x_gmean_gpu = torch.tensor(calibration["x_global_mean"], dtype=torch.float32, device=device)
        x_pca_gpu = torch.tensor(calibration["x_pca_whiten_mat"], dtype=torch.float32, device=device)
        x_knn_bank_gpu = torch.tensor(calibration["x_knn_bank"], dtype=torch.float32, device=device)
        xb_cent = torch.clamp((bx - x_gmean_gpu) * behav_factor_gpu, -12.0, 12.0)
        xb_white = F.normalize(torch.matmul(xb_cent, x_pca_gpu), p=2, dim=-1)
        sim_x = torch.matmul(xb_white, x_knn_bank_gpu.t())
        topx = torch.topk(sim_x, k=min(7, len(x_knn_bank_gpu)), dim=-1).values
        score_x_knn = (1.0 - (0.70 * torch.mean(topx[:, :3], dim=-1) + 0.30 * topx[:, -1])).cpu().numpy()
        if knn_bank_gpu.size(1) == (z_norm_b.size(1) + z_hyp_b.size(1) + xb_white.size(1)):
            z_query_b = F.normalize(torch.cat([z_norm_b, z_hyp_b, 0.50 * xb_white], dim=-1), p=2, dim=-1)
        else:
            z_query_b = z_joint_192
    else:
        score_x_knn = np.zeros(len(X_np), dtype=np.float32)
        z_query_b = z_norm_b

    sim_b = torch.matmul(z_query_b, knn_bank_gpu.t())
    topk_vals = torch.topk(sim_b, k=min(15, len(knn_bank_gpu)), dim=-1).values
    score_knn = (1.0 - (0.65 * torch.mean(topk_vals[:, :5], dim=-1) + 0.35 * topk_vals[:, -1])).cpu().numpy()

    all_z = z_b.cpu().numpy()
    all_raw_logits = raw_l.cpu().numpy()
    all_sc_logits = sc_l.cpu().numpy()
    all_rec = rec.cpu().numpy()
    closed_choice = pred_y.cpu().numpy()
    epist_jsd = out["epistemic_jsd"].cpu().numpy()
    epist_latvar = out["epistemic_latvar"].cpu().numpy()
    logits_ens_np = out["logits_ens"].cpu().numpy()
    input_gates_np = out["input_gates"].cpu().numpy()

    num_known = all_sc_logits.shape[1]
    exp_l = np.exp(all_sc_logits - np.max(all_sc_logits, axis=-1, keepdims=True))
    probs = exp_l / np.sum(exp_l, axis=-1, keepdims=True)
    shannon_ent = -np.sum(probs * np.log(probs + 1e-12), axis=-1) / np.log(max(num_known, 2))
    score_msp = 0.65 * (1.0 - np.max(probs, axis=-1)) + 0.35 * shannon_ent
    lse = np.log(np.sum(exp_l, axis=-1)) + np.max(all_sc_logits, axis=-1)
    score_energy = -lse
    score_tabm_epist = epist_jsd + 0.15 * np.log1p(np.maximum(epist_latvar, 0.0))

    if "W_fc" in calibration:
        mu_G = calibration["mu_G"]
        W_fc = calibration["W_fc"]
        W_diff_norms = calibration["W_diff_norms"]
        P_etf = calibration["P_etf"]
        z_mu = all_z - mu_G
        z_mu_norm = np.linalg.norm(z_mu, axis=-1) + 1e-6
        pred_logits = all_raw_logits[np.arange(len(all_z)), closed_choice][:, None]
        logit_margins = np.maximum(pred_logits - all_raw_logits, 0.0)
        denom_norms = W_diff_norms[closed_choice]
        fdbd_dist = np.sum(logit_margins / denom_norms, axis=-1) / (max(num_known - 1, 1) * z_mu_norm)
        W_pred = W_fc[closed_choice]
        nci_align = np.sum(z_mu * W_pred, axis=-1) / z_mu_norm
        neco_orth = 1.0 - (np.linalg.norm(np.matmul(z_mu, P_etf), axis=-1) / z_mu_norm)
        score_fdbd_nci = (-fdbd_dist * 3.0) + (-nci_align * 0.15) + (neco_orth * 2.5)
    else:
        score_fdbd_nci = score_msp

    class_z_mean = calibration["class_z_mean"]
    class_prec_mats = calibration["class_prec_mats"]
    class_x_mean = calibration["class_x_mean"]
    class_x_std = calibration["class_x_std"]
    class_x_null_proj = calibration["class_x_null_proj"]
    has_sub = "class_z_submeans" in calibration
    has_bounds = "class_x_qlo" in calibration

    score_maha = np.zeros(len(all_z), dtype=np.float32)
    score_inv_viol = np.zeros(len(X_np), dtype=np.float32)
    for k in range(num_known):
        mask_p = closed_choice == k
        if not np.any(mask_p):
            continue
        Zk_lat = all_z[mask_p]
        if has_sub:
            sub_means_k = calibration["class_z_submeans"][k]
            prec_k = class_prec_mats[k]
            maha_min = np.full(len(Zk_lat), 1e9, dtype=np.float32)
            for m_i in range(sub_means_k.shape[0]):
                diff_m = Zk_lat - sub_means_k[m_i : m_i + 1]
                d_m = np.sqrt(np.maximum(np.sum(np.matmul(diff_m, prec_k) * diff_m, axis=-1), 0.0))
                maha_min = np.minimum(maha_min, d_m)
            maha_z = maha_min
        else:
            diff = Zk_lat - class_z_mean[k]
            maha_z = np.sqrt(np.maximum(np.sum(np.matmul(diff, class_prec_mats[k]) * diff, axis=-1), 0.0))

        Xk_sub = X_np[mask_p]
        Zk = np.clip(((Xk_sub - class_x_mean[k]) / class_x_std[k]) * behav_col_factor, -15.0, 15.0)
        null_res = np.linalg.norm(np.matmul(Zk, class_x_null_proj[k]), axis=-1)
        top5_z = np.mean(np.sort(np.abs(Zk), axis=-1)[:, -5:], axis=-1)
        if has_bounds:
            lo_viol = np.maximum(calibration["class_x_qlo"][k] - Xk_sub, 0.0)
            hi_viol = np.maximum(Xk_sub - calibration["class_x_qhi"][k], 0.0)
            viol_ratio = ((lo_viol + hi_viol) / calibration["class_x_iqr"][k]) * behav_col_factor
            inv_v = np.sum(np.log1p(np.minimum(viol_ratio, 50.0)), axis=-1)
        else:
            inv_v = 0.0
        in_k = 0.35 * inv_v + 0.35 * null_res + 0.15 * top5_z + 0.15 * np.sqrt(all_rec[mask_p] + 1e-6)
        score_inv_viol[mask_p] = in_k
        score_maha[mask_p] = maha_z + 0.20 * in_k

    u_vim = calibration["u_vim"]
    NS_global = calibration["NS_global"]
    alpha_vim = float(calibration["alpha_vim"])
    Z_cent = all_z - u_vim.reshape(1, -1)
    v_res = np.linalg.norm(np.matmul(Z_cent, NS_global), axis=-1)
    score_vim = (alpha_vim * v_res) - lse + 0.15 * score_inv_viol

    raw_dict = {
        "closed_choice": closed_choice,
        "energy": score_energy,
        "maha": score_maha,
        "vim": score_vim,
        "knn": score_knn,
        "inv_viol": score_inv_viol,
        "fdbd_nci": score_fdbd_nci,
        "tabm_epist": score_tabm_epist,
        "x_knn": score_x_knn if has_x_knn else score_inv_viol,
        "msp": score_msp,
    }

    prim_keys = ["energy", "maha", "vim", "knn", "inv_viol", "fdbd_nci", "tabm_epist", "x_knn", "msp"]
    num_p = min(len(prim_keys), calibration["cal_sorted_quantiles"].shape[0])
    norm_prims = np.zeros((num_p, len(closed_choice)), dtype=np.float32)
    for p_idx in range(num_p):
        norm_prims[p_idx] = transform_probit_survival_score(
            raw_dict[prim_keys[p_idx]],
            closed_choice,
            calibration["cal_sorted_quantiles"][p_idx],
            calibration["cal_q98"][p_idx],
            calibration["cal_iqr"][p_idx],
        )

    meta_scores = compute_synergistic_meta_score(norm_prims, calibration["meta_weights"])
    tau_red = calibration["class_meta_tau"][closed_choice]
    tau_amber = tau_red * 0.72

    return {
        "probs": probs,
        "closed_choice": closed_choice,
        "shannon_entropy": shannon_ent,
        "epistemic_jsd": epist_jsd,
        "epistemic_latvar": epist_latvar,
        "meta_score": meta_scores,
        "tau_amber": tau_amber,
        "tau_red": tau_red,
        "primitives": {prim_keys[i]: norm_prims[i] for i in range(num_p)},
        "z_joint_192": z_joint_192.cpu().numpy(),
        "input_gates": input_gates_np,
        "recon_mse_per_feat": rec_per_feat,
        "logits_ens": logits_ens_np,
    }


def compute_class_locked_ig_shap_and_lime(
    model: AegisFlowZenithV8,
    x_scaled_1d: np.ndarray,
    calibration: Dict[str, Any],
    raw_feature_names: List[str],
    use_qt: bool,
    target_class: int,
    device: torch.device,
    ig_steps: int = 32,
    lime_samples: int = 4096,
) -> List[Dict[str, Any]]:
    """Class-Locked C^inf IG-SHAP + 4,096-Sample GPU-LIME + Counterfactual Normal Target."""
    model.eval()
    D_raw = len(raw_feature_names)
    x_t = torch.tensor(x_scaled_1d, dtype=torch.float32, device=device).unsqueeze(0)
    benign_baseline = torch.tensor(
        calibration["class_x_mean"][0], dtype=torch.float32, device=device
    ).unsqueeze(0)

    # 1. Class-Locked Integrated Gradients (SHAP path from benign mean -> x)
    alphas = torch.linspace(0.0, 1.0, ig_steps, device=device).view(-1, 1)
    interp = (benign_baseline + alphas * (x_t - benign_baseline)).detach().requires_grad_(True)
    cond_y = torch.full((ig_steps,), int(target_class), dtype=torch.long, device=device)
    out = model(interp, cond_labels=cond_y)
    target_score = out["logits"][:, target_class].sum()
    grads = torch.autograd.grad(target_score, interp)[0]
    avg_grads = grads.mean(dim=0, keepdim=True)
    ig_attr = ((x_t - benign_baseline) * avg_grads).squeeze(0).detach().cpu().numpy()

    # 2. 4,096-Sample GPU-LIME via local Gaussian perturbation + ridge regression
    with torch.no_grad():
        noise = torch.randn(lime_samples, x_t.size(1), device=device) * 0.25
        perturbed = x_t + noise
        logits_p = model(perturbed)["logits"][:, target_class]
        dist_sq = torch.sum(noise ** 2, dim=-1)
        weights = torch.exp(-dist_sq / (2.0 * (0.75 ** 2)))
        W_sqrt = torch.sqrt(weights).unsqueeze(1)
        A = noise * W_sqrt
        b = (logits_p - logits_p.mean()) * W_sqrt.squeeze(1)
        AtA = torch.matmul(A.t(), A) + 1.0 * torch.eye(A.size(1), device=device)
        Atb = torch.matmul(A.t(), b)
        lime_w = torch.linalg.solve(AtA, Atb).cpu().numpy()

        out_single = model(x_t, cond_labels=torch.tensor([target_class], device=device))
        gates = out_single["input_gates"].squeeze(0).cpu().numpy()
        recon_mse = ((x_t - out_single["x_recon_cond"]) ** 2).squeeze(0).cpu().numpy()

    benign_mean_np = calibration["class_x_mean"][0]
    benign_std_np = np.maximum(calibration["class_x_std"][0], 1e-6)

    # Collapse paired quantile twin back to canonical raw features
    rows = []
    for j in range(D_raw):
        shap_val = float(ig_attr[j] + (ig_attr[j + D_raw] if use_qt and j + D_raw < len(ig_attr) else 0.0))
        lime_val = float(lime_w[j] + (lime_w[j + D_raw] if use_qt and j + D_raw < len(lime_w) else 0.0))
        gate_val = float(gates[j])
        mse_val = float(recon_mse[j])
        z_dev = float((x_scaled_1d[j] - benign_mean_np[j]) / benign_std_np[j])
        cf_delta = float(benign_mean_np[j] - x_scaled_1d[j])
        rows.append({
            "feature": raw_feature_names[j],
            "ig_shap": round(shap_val, 4),
            "gpu_lime": round(lime_val, 4),
            "lfg_gate": round(gate_val, 4),
            "recon_mse": round(mse_val, 4),
            "z_deviation": round(z_dev, 2),
            "counterfactual_delta": round(cf_delta, 4),
        })

    rows.sort(key=lambda r: abs(r["ig_shap"]) + 0.5 * abs(r["gpu_lime"]), reverse=True)
    return rows[:5]
