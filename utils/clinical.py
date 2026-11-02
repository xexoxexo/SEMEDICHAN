"""Validasi data klinis terstruktur (ICD-10, alergi, obat)."""
from __future__ import annotations

import re

ICD10_RE = re.compile(r"^[A-TV-Z][0-9]{2}(\.[0-9A-Z]{1,4})?$")


def parse_icd10(text: str) -> tuple[list[str], str | None]:
    codes = [c.strip().upper() for c in re.split(r"[,\n;]+", text or "") if c.strip()]
    bad = [c for c in codes if not ICD10_RE.match(c)]
    if bad:
        return [], "Kode ICD-10 tidak valid: " + ", ".join(bad) + " (contoh: J20.9, E11)."
    return list(dict.fromkeys(codes)), None


def parse_lines(text: str, limit: int = 50) -> list[str]:
    return [ln.strip()[:120] for ln in (text or "").splitlines() if ln.strip()][:limit]


def clean_medications(rows) -> list[dict]:
    out = []
    for r in rows or []:
        name = str(r.get("nama") or "").strip()
        if not name:
            continue
        out.append({"nama": name[:120], "dosis": str(r.get("dosis") or "").strip()[:60],
                    "frekuensi": str(r.get("frekuensi") or "").strip()[:60], "durasi": str(r.get("durasi") or "").strip()[:60]})
    return out[:30]
