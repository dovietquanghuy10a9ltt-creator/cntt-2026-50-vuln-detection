"""Bước 9: độ dài token theo tokenizer của UniXcoder (microsoft/unixcoder-base-nine, revision cố định).

Khuôn mã hóa: <s> <encoder-only> </s> CODE </s>  -> độ dài = số token của CODE + 4 (giống unixcoder.py, chế độ
<encoder-only>). Báo cáo theo ngôn ngữ: trung vị, p90, p99, dài nhất, tỷ lệ vượt 768 và vượt 512.
Tokenizer tải về cvefixes_work/hf_cache.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

C.check_package_hashes()
MODEL = "microsoft/unixcoder-base-nine"
REVISION = "5f0dc256eb0904af496d427451da5d7f90261676"
MAX_LEN, CODEBERT_LEN, N_SPECIAL = 768, 512, 4
UNITS = C.WORK / "units_v1.parquet"
FOLDS_V2 = C.WORK / "groups_and_folds_cvefixes_v2.csv"
INTER = C.WORK / "intermediate"
OUT = INTER / "token_lengths.parquet"
REPORT_MD = INTER / "step9.md"
REPORT_JSON = INTER / "step9.json"
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")


def main():
    from transformers import AutoTokenizer
    import transformers
    tok = AutoTokenizer.from_pretrained(MODEL, revision=REVISION, cache_dir=str(C.WORK / "hf_cache"))
    enc_id = tok.convert_tokens_to_ids("<encoder-only>")
    assert enc_id is not None and enc_id != tok.unk_token_id, "Tokenizer không có token <encoder-only>"

    units = pd.read_parquet(UNITS, columns=["unit_id", "func", "language", "target"])
    v2_ids = set(pd.read_csv(FOLDS_V2, usecols=["unit_id"]).unit_id)
    lens = []
    funcs = units.func.tolist()
    for i in range(0, len(funcs), 256):
        ids = tok(funcs[i:i + 256], add_special_tokens=False)["input_ids"]
        lens.extend(len(x) for x in ids)
    units["n_code_tokens"] = np.array(lens, dtype="int64")
    units["n_tokens"] = units.n_code_tokens + N_SPECIAL
    # kiểm tra khuôn trên một hàm: tự dựng chuỗi id đầy đủ như unixcoder.py
    t0 = tok.tokenize(funcs[0])
    full = [tok.cls_token, "<encoder-only>", tok.sep_token] + t0[:MAX_LEN - N_SPECIAL] + [tok.sep_token]
    assert len(t0) == units.n_code_tokens.iloc[0] and len(full) == min(units.n_tokens.iloc[0], MAX_LEN)
    units["in_v2"] = units.unit_id.isin(v2_ids)
    units[["unit_id", "language", "target", "in_v2", "n_code_tokens", "n_tokens"]].to_parquet(OUT, index=False)

    md, js = [], {}
    w = md.append
    w("## Bước 9: độ dài token (UniXcoder)\n")
    w(f"Tokenizer `{MODEL}` revision `{REVISION}` (transformers {transformers.__version__}, lớp `{type(tok).__name__}`). "
      f"Độ dài = số token của mã + {N_SPECIAL} token đặc biệt (`<s> <encoder-only> </s> CODE </s>`); mã hóa trên `func` nguyên bản. "
      f"Vượt {MAX_LEN}: mã dài hơn {MAX_LEN - N_SPECIAL} token sẽ bị cắt. Cột *vượt 512* dùng cùng cách đếm (tham khảo cho CodeBERT, giới hạn 512).\n")
    for name, u in (("v2", units[units.in_v2]), ("v1", units)):
        rows = []
        for l in C.LANGS + ["Tổng"]:
            s = u if l == "Tổng" else u[u.language == l]
            n = s.n_tokens
            rows.append({"ngôn ngữ": l, "số đơn vị": len(s), "trung vị": float(n.median()),
                         "p90": float(n.quantile(.9)), "p99": float(n.quantile(.99)), "dài nhất": int(n.max()),
                         f"% vượt {MAX_LEN}": round(100 * float((n > MAX_LEN).mean()), 1),
                         f"% vượt {CODEBERT_LEN}": round(100 * float((n > CODEBERT_LEN).mean()), 1)})
        t = pd.DataFrame(rows)
        w(f"Tập {name}:\n")
        w(C.md_table(t) + "\n")
        js[name] = t.to_dict(orient="records")
        print(f"\n{name}:\n" + t.to_string(index=False))
    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    REPORT_JSON.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
