"""IP klien untuk pembatas laju. X-Forwarded-For hanya dipercaya bila TRUST_PROXY_HEADERS=1 (di belakang proxy)."""
from __future__ import annotations

import config


def client_ip() -> str:
    try:
        import streamlit as st

        ctx = st.context
        if config.TRUST_PROXY_HEADERS:
            xff = ctx.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[-1].strip()   # entri paling kanan ditambahkan proxy tepercaya
        return getattr(ctx, "ip_address", None) or "unknown"
    except Exception:  # noqa: BLE001 - di luar konteks Streamlit/uji
        return "unknown"
