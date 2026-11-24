"""Bước 8: đối chiếu CVEfixes với MVD bằng mvd_reference.csv.

- Trùng CVE theo ngôn ngữ, trùng hàm (unit_id).
- Thêm hai cột in_mvd_cve (đơn vị có ít nhất một CVE thuộc MVD, xét CVE của MVD ở mọi ngôn ngữ) và in_mvd_func
  (unit_id có trong MVD) vào units_v1.parquet (ghi đè có kiểm soát; chạy lại 06_units_v1.py thì phải chạy lại script này).
- Đếm đơn vị v2 có in_mvd_cve sai, theo ngôn ngữ và nhãn (tập "huấn luyện trên MVD, kiểm tra trên CVEfixes").
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import pandas as pd  # noqa: E402

C.check_package_hashes()
UNITS = C.WORK / "units_v1.parquet"
FOLDS_V2 = C.WORK / "groups_and_folds_cvefixes_v2.csv"
MVD = C.ROOT / "mvd_reference.csv"
INTER = C.WORK / "intermediate"
REPORT_MD = INTER / "step8.md"
REPORT_JSON = INTER / "step8.json"


def cves(s) -> set:
    return {c for c in str(s).split(";") if c}


def main():
    mvd = pd.read_csv(MVD)
    assert mvd.unit_id.is_unique and len(mvd) == 18694
    mvd_cve_all = set().union(*mvd.cves.map(cves))
    mvd_cve_lang = {l: set().union(*mvd[mvd.language == l].cves.map(cves)) for l in C.LANGS}
    mvd_ids = set(mvd.unit_id)
    mvd_by_id = mvd.set_index("unit_id")

    units = pd.read_parquet(UNITS)
    units = units.drop(columns=[c for c in ("in_mvd_cve", "in_mvd_func") if c in units.columns])
    v2_ids = set(pd.read_csv(FOLDS_V2, usecols=["unit_id"]).unit_id)
    units["in_mvd_cve"] = units.all_cves.map(lambda s: bool(cves(s) & mvd_cve_all))
    units["in_mvd_func"] = units.unit_id.isin(mvd_ids)
    tmp = UNITS.with_suffix(".parquet.tmp")
    units.to_parquet(tmp, index=False, compression="zstd")
    tmp.replace(UNITS)
    v2 = units[units.unit_id.isin(v2_ids)]
    assert len(v2) == len(v2_ids)

    md, js = [], {}
    w = md.append
    w("## Bước 8: đối chiếu với MVD\n")
    w(f"`mvd_reference.csv`: {len(mvd):,} hàm, {len(mvd_cve_all):,} CVE. `in_mvd_cve` xét CVE của MVD ở mọi ngôn ngữ; "
      "cột *cùng ngôn ngữ* chỉ xét CVE của MVD trong đúng ngôn ngữ đó.\n")

    rows = []
    for name, u in (("v1", units), ("v2", v2)):
        for l in C.LANGS + ["Tổng"]:
            s = u if l == "Tổng" else u[u.language == l]
            cs = set().union(*s.all_cves.map(cves)) if len(s) else set()
            same = mvd_cve_all if l == "Tổng" else mvd_cve_lang[l]
            rows.append({"tập": name, "ngôn ngữ": l, "số CVE (CVEfixes)": len(cs),
                         "có trong MVD (mọi ngôn ngữ)": len(cs & mvd_cve_all),
                         "có trong MVD (cùng ngôn ngữ)": len(cs & same),
                         "chỉ có ở CVEfixes": len(cs - mvd_cve_all)})
    ct = pd.DataFrame(rows)
    w("### Trùng CVE\n")
    w(C.md_table(ct) + "\n")

    rows = []
    for name, u in (("v1", units), ("v2", v2)):
        for l in C.LANGS + ["Tổng"]:
            s = u if l == "Tổng" else u[u.language == l]
            hit = s[s.in_mvd_func]
            m = mvd_by_id.loc[hit.unit_id] if len(hit) else mvd_by_id.iloc[:0]
            rows.append({"tập": name, "ngôn ngữ": l, "đơn vị": len(s), "unit_id trùng MVD": len(hit),
                         "% trùng": round(100 * len(hit) / max(1, len(s)), 2),
                         "cùng ngôn ngữ": int((m.language.values == hit.language.values).sum()),
                         "cùng nhãn": int((m.target.values == hit.target.values).sum()),
                         "trùng với MVD v2": int(m.in_v2.sum())})
    ft = pd.DataFrame(rows)
    w("### Trùng hàm (unit_id)\n")
    w(C.md_table(ft) + "\n")

    rows = []
    for l in C.LANGS + ["Tổng"]:
        s = v2 if l == "Tổng" else v2[v2.language == l]
        new = s[~s.in_mvd_cve]
        rows.append({"ngôn ngữ": l, "đơn vị v2": len(s), "in_mvd_cve sai: t=1": int((new.target == 1).sum()),
                     "in_mvd_cve sai: t=0": int((new.target == 0).sum()), "in_mvd_cve sai: tổng": len(new),
                     "% đơn vị v2": round(100 * len(new) / max(1, len(s)), 1),
                     "trong đó in_mvd_func đúng": int(new.in_mvd_func.sum())})
    nt = pd.DataFrame(rows)
    w("### Đơn vị v2 có CVE hoàn toàn mới so với MVD (`in_mvd_cve` sai)\n")
    w("Tập dùng cho thí nghiệm \"huấn luyện trên MVD, kiểm tra trên các CVE chỉ có ở CVEfixes\".\n")
    w(C.md_table(nt) + "\n")
    lack = [r["ngôn ngữ"] for r in rows if r["ngôn ngữ"] != "Tổng" and (r["in_mvd_cve sai: t=1"] == 0 or r["in_mvd_cve sai: t=0"] == 0)]
    w("Ngôn ngữ thiếu một nhãn trong tập này: " + (", ".join(lack) if lack else "không có.") + "\n")
    leak = v2[~v2.in_mvd_cve & v2.in_mvd_func]
    if len(leak):
        w(f"Lưu ý: {len(leak):,} đơn vị v2 có CVE không thuộc MVD nhưng `unit_id` lại có trong MVD (cùng hàm, khác CVE); "
          "nên loại thêm các đơn vị này khỏi tập kiểm tra để tránh rò rỉ.\n")
    js.update({"cve_overlap": ct.to_dict(orient="records"), "func_overlap": ft.to_dict(orient="records"),
               "new_cve_units_v2": nt.to_dict(orient="records"), "langs_missing_label_new": lack})

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    REPORT_JSON.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")
    pd.set_option("display.width", 250)
    print(ct.to_string(index=False))
    print(ft.to_string(index=False))
    print(nt.to_string(index=False))


if __name__ == "__main__":
    main()
