#!/usr/bin/env python3
"""
compare_ml.py — Full-grid model comparison for cookie classification.

Compares Random Forest vs ExtraTrees vs HistGradientBoosting vs XGBoost vs
LightGBM vs Logistic Regression on the CURRENT dataset with production
features, family-aware splitting, Strict-first ranking, threshold sweeps,
and deployability (JSON size) scoring.

Feature/label/split code is imported from train.py so the comparison always
tests production features (fixes the drift that made this file stale).

Usage:
  python3 compare_ml.py [--data DATA/merged_balanced_strict.json]
                        [--out-dir compare_results] [--smoke]
  --smoke: 60-second pipeline check (subsampled data, 2 tiny configs).
"""
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

import argparse
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone

import numpy as np

from train import (
    LABEL_MAP,
    cookie_family_key,
    export_tree,
    extract_numerical,
    iter_observations,
)
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedGroupKFold
from xgboost import XGBClassifier
import lightgbm as lgb

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

CLASSES = ["Advertising", "Functionality", "Performance", "Strict"]
STR2INT = {c: i for i, c in enumerate(CLASSES)}
THRESHOLDS = [0.30, 0.35, 0.40, 0.50, 0.60]
RANDOM_STATE = 42


def load_data(path):
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    records = [v for v in raw.values() if v.get("label") in LABEL_MAP]
    cookies = []
    for cookie in records:
        group = cookie_family_key(cookie)
        for observation in iter_observations(cookie):
            sample = dict(cookie)
            sample["variable_data"] = [observation]
            sample["_group"] = group
            cookies.append(sample)
    return records, cookies


def build_features(cookies, max_ngrams):
    X_num = np.array([extract_numerical(c) for c in cookies], dtype=np.float32)
    y = np.array([LABEL_MAP[c["label"]] for c in cookies])
    names = [c.get("name", "").lower() for c in cookies]
    groups = np.array([c["_group"] for c in cookies])
    tfidf = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(1, 5),
        max_features=max_ngrams, min_df=2, sublinear_tf=True,
    )
    X_ng = tfidf.fit_transform(names).toarray().astype(np.float32)
    X = np.hstack([X_num, X_ng])
    return X, y, groups, X_num.shape[1], X_ng.shape[1]


def to_int_labels(y_str):
    return np.array([STR2INT[c] for c in y_str])


def threshold_stats(y_true, y_pred, y_prob, thresholds):
    out = {}
    max_p = y_prob.max(axis=1)
    for t in thresholds:
        m = max_p >= t
        n = int(m.sum())
        if n == 0:
            out[f"{t:.2f}"] = {"coverage": 0.0, "acc": 0.0, "n": 0}
        else:
            out[f"{t:.2f}"] = {
                "coverage": round(float(n) / len(y_true), 4),
                "acc": round(float((y_pred[m] == y_true[m]).mean()), 4),
                "n": n,
            }
    return out


def estimate_tree_json_kb(model):
    try:
        blob = json.dumps([export_tree(e) for e in model.estimators_],
                          separators=(",", ":"))
        return round(len(blob) / 1024.0, 1)
    except Exception:
        return None


def eval_fitted(name, model, X_te, y_te_str, train_secs, extra=None):
    t0 = time.time()
    y_pred = model.predict(X_te)
    infer_ms = (time.time() - t0) / max(len(X_te), 1) * 1000.0
    if isinstance(y_pred[0], (int, np.integer)):
        y_pred = np.array([CLASSES[i] for i in y_pred])
    y_prob = model.predict_proba(X_te)
    # Align proba columns to CLASSES order. Int-label models (xgb/lgb/hgb)
    # store classes_ as ints; string-label models store names.
    if hasattr(model, "classes_"):
        cls = list(model.classes_)
        if cls and isinstance(cls[0], (int, np.integer)):
            order = [STR2INT[c] for c in CLASSES]
        else:
            order = [cls.index(c) for c in CLASSES]
        y_prob = y_prob[:, order]
    acc = accuracy_score(y_te_str, y_pred)
    report = classification_report(y_te_str, y_pred, output_dict=True,
                                   zero_division=0)
    conf = confusion_matrix(y_te_str, y_pred, labels=CLASSES)
    strict = report.get("Strict", {})
    row = {
        "name": name,
        "test_acc": round(float(acc), 4),
        "macro_f1": round(float(report["macro avg"]["f1-score"]), 4),
        "weighted_f1": round(float(report["weighted avg"]["f1-score"]), 4),
        "strict_precision": round(float(strict.get("precision", 0.0)), 4),
        "strict_recall": round(float(strict.get("recall", 0.0)), 4),
        "strict_f1": round(float(strict.get("f1-score", 0.0)), 4),
        "train_secs": round(float(train_secs), 1),
        "infer_ms": round(float(infer_ms), 4),
        "thresholds": threshold_stats(y_te_str, np.asarray(y_pred), y_prob,
                                      THRESHOLDS),
        "per_class_f1": {c: round(float(report.get(c, {}).get("f1-score", 0.0)), 4)
                         for c in CLASSES},
        "confusion": conf.tolist(),
        "tree_json_kb": estimate_tree_json_kb(model)
        if hasattr(model, "estimators_") else None,
    }
    if extra:
        row.update(extra)
    return row


def fit_and_eval(name, make_model, X_tr, y_tr, X_te, y_te_str,
                 use_int_labels=False, sample_weight=None, extra=None):
    model = make_model()
    t0 = time.time()
    if use_int_labels:
        if sample_weight is not None:
            model.fit(X_tr, to_int_labels(y_tr), sample_weight=sample_weight)
        else:
            model.fit(X_tr, to_int_labels(y_tr))
    else:
        model.fit(X_tr, y_tr)
    train_secs = time.time() - t0
    return eval_fitted(name, model, X_te, y_te_str, train_secs, extra), model


def inverse_freq_weights(y_tr):
    counts = Counter(y_tr)
    total = len(y_tr)
    return np.array([total / (len(CLASSES) * counts[c]) for c in y_tr])


def define_grids():
    grids = []
    # 1. Random Forest — incumbent, bigger grid (27 fits)
    for n in (200, 350, 500):
        for depth in (12, 16, 24):
            for strict_w in (3, 5, 8):
                grids.append((
                    f"RF n={n} d={depth} wStrict={strict_w}",
                    "rf",
                    dict(n_estimators=n, max_depth=depth,
                         min_samples_leaf=2, max_features="sqrt",
                         class_weight={"Strict": strict_w, "Functionality": 1,
                                       "Performance": 1, "Advertising": 1},
                         random_state=RANDOM_STATE, n_jobs=-1),
                ))
    # 2. ExtraTrees — drop-in deploy (same tree JSON format) (4 fits)
    for n in (200, 350):
        for depth in (16, 24):
            grids.append((
                f"ET n={n} d={depth}",
                "et",
                dict(n_estimators=n, max_depth=depth, min_samples_leaf=2,
                     max_features="sqrt",
                     class_weight={"Strict": 5, "Functionality": 1,
                                   "Performance": 1, "Advertising": 1},
                     random_state=RANDOM_STATE, n_jobs=-1),
            ))
    # 3. HistGradientBoosting (8 fits)
    for lr in (0.05, 0.1):
        for depth in (8, 12):
            for leaves in (63, 127):
                grids.append((
                    f"HGB lr={lr} d={depth} leaves={leaves}",
                    "hgb",
                    dict(learning_rate=lr, max_depth=depth,
                         max_leaf_nodes=leaves, l2_regularization=1.0,
                         random_state=RANDOM_STATE),
                ))
    # 4. XGBoost (8 fits)
    for depth in (6, 10):
        for rounds in (300, 600):
            for lr in (0.05, 0.1):
                grids.append((
                    f"XGB d={depth} rounds={rounds} lr={lr}",
                    "xgb",
                    dict(n_estimators=rounds, max_depth=depth,
                         learning_rate=lr, subsample=0.8,
                         colsample_bytree=0.8, random_state=RANDOM_STATE,
                         n_jobs=-1, eval_metric="mlogloss"),
                ))
    # 5. LightGBM (8 fits)
    for leaves in (63, 127):
        for rounds in (300, 600):
            for lr in (0.05, 0.1):
                grids.append((
                    f"LGB leaves={leaves} rounds={rounds} lr={lr}",
                    "lgb",
                    dict(n_estimators=rounds, num_leaves=leaves,
                         max_depth=-1, learning_rate=lr, subsample=0.8,
                         colsample_bytree=0.8, random_state=RANDOM_STATE,
                         n_jobs=-1, verbosity=-1),
                ))
    # 6. Logistic Regression control (3 fits; n_jobs removed: no-op in sklearn 1.8+)
    for c in (0.1, 1.0, 10.0):
        grids.append((
            f"LR C={c}",
            "lr",
            dict(C=c, max_iter=2000, class_weight="balanced",
                 solver="saga", random_state=RANDOM_STATE),
        ))
    return grids


def make_model(kind, params, n_classes):
    if kind == "rf":
        return RandomForestClassifier(**params)
    if kind == "et":
        return ExtraTreesClassifier(**params)
    if kind == "hgb":
        return HistGradientBoostingClassifier(**params)
    if kind == "xgb":
        return XGBClassifier(**params)
    if kind == "lgb":
        return lgb.LGBMClassifier(objective="multiclass",
                                  num_class=n_classes, **params)
    if kind == "lr":
        return LogisticRegression(**params)
    raise ValueError(kind)


def print_table(rows):
    print(f"\n{'=' * 110}")
    print("  MODEL COMPARISON (ranked: Strict-recall > weighted-F1 > accuracy)")
    print(f"{'=' * 110}")
    print(f"  {'Model':34s} {'Acc':>7s} {'W.F1':>7s} {'M.F1':>7s} "
          f"{'Str-P':>7s} {'Str-R':>7s} {'T.30cov':>8s} {'T.30acc':>8s} "
          f"{'Train':>8s} {'Infer':>9s} {'JSON_KB':>8s}")
    for r in rows:
        t30 = r["thresholds"]["0.30"]
        kb = f"{r['tree_json_kb']:.1f}" if r["tree_json_kb"] else "-"
        print(f"  {r['name']:34s} {r['test_acc'] * 100:6.2f}% "
              f"{r['weighted_f1']:7.4f} {r['macro_f1']:7.4f} "
              f"{r['strict_precision']:7.4f} {r['strict_recall']:7.4f} "
              f"{t30['coverage']:8.4f} {t30['acc']:8.4f} "
              f"{r['train_secs']:7.1f}s {r['infer_ms']:8.4f}ms {kb:>8s}")
    print(f"\n  Per-class F1:")
    header = f"  {'Class':15s}"
    for r in rows[:8]:
        header += f" {r['name'][:14]:>15s}"
    print(header)
    for cls in CLASSES:
        print(f"  {cls:15s}" + "".join(
            f" {r['per_class_f1'][cls]:15.4f}" for r in rows[:8]))
    print(f"\n  Winner (Strict-R → W.F1 → acc): {rows[0]['name']}")
    print(f"  Runner-up: {rows[1]['name'] if len(rows) > 1 else '-'}")
    print(f"{'=' * 110}")


def rank_key(r):
    return (r["strict_recall"], r["weighted_f1"], r["test_acc"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="DATA/merged_balanced_strict.json")
    ap.add_argument("--out-dir", default="compare_results")
    ap.add_argument("--smoke", action="store_true",
                    help="60s pipeline check: subsampled data, 2 tiny configs")
    ap.add_argument("--only-kind", default=None,
                    help="run only one model family: rf, et, hgb, xgb, lgb, lr "
                         "(lets you chunk a long run; skips winner stage)")
    ap.add_argument("--resume", action="store_true",
                    help="skip configs already present in OUT-DIR/checkpoint.json")
    args = ap.parse_args()

    print(f"Loading {args.data}...")
    records, cookies = load_data(args.data)
    print(f"  {len(records)} cookie records, {len(cookies)} observations — "
          f"{dict(Counter(LABEL_MAP[c['label']] for c in cookies).most_common())}")

    if args.smoke:
        step = max(len(cookies) // 4000, 1)
        cookies = cookies[::step]
        print(f"  SMOKE: subsampled to {len(cookies)} observations")

    print("Building features (production parity via train.py)...")
    X, y, groups, n_num, n_ng = build_features(cookies, 300)
    print(f"  {n_num} numerical + {n_ng} n-gram = {X.shape[1]} total")

    holdout = StratifiedGroupKFold(n_splits=5, shuffle=True,
                                   random_state=RANDOM_STATE)
    tr_idx, te_idx = next(holdout.split(X, y, groups))
    X_tr, X_te = X[tr_idx], X[te_idx]
    y_tr, y_te = y[tr_idx], y[te_idx]
    print(f"Train: {len(X_tr)}  Test: {len(X_te)} "
          f"(families tr={len(set(groups[tr_idx]))} te={len(set(groups[te_idx]))})")

    sw = inverse_freq_weights(y_tr)
    grids = define_grids()
    if args.only_kind:
        grids = [g for g in grids if g[1] == args.only_kind]
        print(f"  --only-kind={args.only_kind}: {len(grids)} configs")
    if args.smoke:
        grids = [
            ("RF-smoke n=30 d=8", "rf",
             dict(n_estimators=30, max_depth=8, min_samples_leaf=2,
                  max_features="sqrt",
                  class_weight={"Strict": 5, "Functionality": 1,
                                "Performance": 1, "Advertising": 1},
                  random_state=RANDOM_STATE, n_jobs=-1)),
            ("LR-smoke C=1", "lr",
             dict(C=1.0, max_iter=2000, class_weight="balanced",
                  solver="saga", random_state=RANDOM_STATE)),
        ]

    rows = []
    fitted = {}
    if args.resume:
        ckpt = os.path.join(args.out_dir, "checkpoint.json")
        if os.path.exists(ckpt):
            try:
                with open(ckpt, encoding="utf-8") as f:
                    prev = json.load(f).get("rows", [])
                done = {r["name"] for r in prev}
                before = len(grids)
                grids = [g for g in grids if g[0] not in done]
                rows = list(prev)
                print(f"  --resume: keeping {len(rows)} completed, "
                      f"{len(grids)} remaining (of {before})")
            except Exception as e:
                print(f"  --resume: checkpoint unreadable ({e}), running all")
    total = len(grids)
    os.makedirs(args.out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    checkpoint_path = os.path.join(args.out_dir, "checkpoint.json")

    def checkpoint(rows_done):
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump({
                "meta": {
                    "data": args.data,
                    "n_records": len(records),
                    "n_observations": len(cookies),
                    "n_features": int(X.shape[1]),
                    "split": "StratifiedGroupKFold(5,seed=42) first fold",
                    "n_train": len(X_tr),
                    "n_test": len(X_te),
                    "ranking": "strict_recall > weighted_f1 > test_acc",
                    "stamp": stamp,
                    "smoke": bool(args.smoke),
                    "completed": len(rows_done),
                    "total": total,
                },
                "rows": rows_done,
            }, f)
    for i, (name, kind, params) in enumerate(grids, 1):
        print(f"[{i}/{total}] {name} ...", flush=True)
        use_int = kind in ("xgb", "lgb", "hgb")
        w = sw if kind in ("xgb", "lgb", "hgb") else None
        row, model = fit_and_eval(
            name, lambda p=params, k=kind: make_model(k, p, len(CLASSES)),
            X_tr, y_tr, X_te, y_te, use_int_labels=use_int,
            sample_weight=w,
            extra={"kind": kind, "params": {str(k): v for k, v in params.items()}},
        )
        rows.append(row)
        fitted[name] = (kind, params, model)
        print(f"         acc={row['test_acc']:.4f} strict-R={row['strict_recall']:.4f} "
              f"wF1={row['weighted_f1']:.4f} train={row['train_secs']}s",
              flush=True)
        checkpoint(rows)

    rows.sort(key=rank_key, reverse=True)
    print_table(rows)

    payload = {
        "meta": {
            "data": args.data,
            "n_records": len(records),
            "n_observations": len(cookies),
            "n_features": int(X.shape[1]),
            "split": "StratifiedGroupKFold(5,seed=42) first fold",
            "n_train": len(X_tr),
            "n_test": len(X_te),
            "ranking": "strict_recall > weighted_f1 > test_acc",
            "stamp": stamp,
            "smoke": bool(args.smoke),
        },
        "rows": rows,
    }
    out_path = os.path.join(args.out_dir, "results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    with open(os.path.join(args.out_dir, "results_table.txt"), "w",
              encoding="utf-8") as f:
        f.write(f"winner: {rows[0]['name']}\n")
        for r in rows:
            f.write(
                f"{r['name']} acc={r['test_acc']} wF1={r['weighted_f1']} "
                f"mF1={r['macro_f1']} strP={r['strict_precision']} "
                f"strR={r['strict_recall']} t30={r['thresholds']['0.30']} "
                f"train={r['train_secs']}s infer={r['infer_ms']}ms "
                f"kb={r['tree_json_kb']}\n")
    print(f"\nSaved {out_path}")

    if not args.smoke and not args.only_kind:
        # Winner TF-IDF widening stage (300 -> 500), winner config only.
        winner = rows[0]
        if winner["name"] in fitted:
            kind, params, _ = fitted[winner["name"]]
        else:
            # Resumed run: winner was restored from checkpoint; its full
            # config is stored in the row (JSON round-trip safe).
            kind, params = winner["extra"]["kind"], dict(
                winner["extra"]["params"])
        print(f"\nWinner TF-IDF widening: {winner['name']} "
              f"(300 -> 500 n-grams)...")
        Xw, _, _, _, n_ng_w = build_features(cookies, 500)
        Xw_tr, Xw_te = Xw[tr_idx], Xw[te_idx]
        use_int = kind in ("xgb", "lgb", "hgb")
        w = inverse_freq_weights(y_tr) if use_int else None
        wrow, _ = fit_and_eval(
            winner["name"] + " +tfidf500",
            lambda: make_model(kind, params, len(CLASSES)),
            Xw_tr, y_tr, Xw_te, y_te, use_int_labels=use_int,
            sample_weight=w, extra={"kind": kind + "+tfidf500"},
        )
        print(f"  base300: acc={winner['test_acc']} wF1={winner['weighted_f1']} "
              f"strR={winner['strict_recall']} kb={winner['tree_json_kb']}")
        print(f"  wide500: acc={wrow['test_acc']} wF1={wrow['weighted_f1']} "
              f"strR={wrow['strict_recall']} kb={wrow['tree_json_kb']}")
        payload["winner_wide500"] = wrow
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        print(f"Updated {out_path} with winner_wide500")


if __name__ == "__main__":
    main()
