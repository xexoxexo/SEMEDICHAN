"""Modul helper untuk pencocokan otomatis label kategori penyakit menggunakan dataset yang disinkronisasi."""
from __future__ import annotations
import pandas as pd
from pathlib import Path

# Path dataset bersih
DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "disease_classes_cleaned.csv"

_MAPPING_CACHE = None

def _load_mapping() -> dict[str, str]:
    global _MAPPING_CACHE
    if _MAPPING_CACHE is not None:
        return _MAPPING_CACHE
    
    if not DATA_PATH.exists():
        return {}
    
    df = pd.read_csv(DATA_PATH)
    # Buat dictionary: lowercase(Disease Name) -> Disease Class
    mapping = {}
    for _, row in df.iterrows():
        name = str(row.get("Disease Name", "")).strip().lower()
        cls = str(row.get("Disease Class", "")).strip()
        if name:
            mapping[name] = cls
            
    _MAPPING_CACHE = mapping
    return _MAPPING_CACHE

def predict_disease_class(diagnosis_text: str) -> dict[str, str]:
    """
    Mencocokkan teks diagnosis dengan kelas penyakit berdasarkan dataset ICD/Pathways.
    Mengembalikan dict dengan Disease Name yang cocok dan Disease Class-nya.
    """
    if not diagnosis_text:
        return {"matched_disease": None, "disease_class": "Unclassified"}
        
    mapping = _load_mapping()
    text_lower = diagnosis_text.strip().lower()
    
    # 1. Exact match
    if text_lower in mapping:
        return {"matched_disease": diagnosis_text, "disease_class": mapping[text_lower]}
        
    # 2. Substring match (cari apakah nama penyakit ada di dalam teks diagnosis)
    for disease_name, disease_class in mapping.items():
        if disease_name in text_lower or text_lower in disease_name:
            return {"matched_disease": disease_name, "disease_class": disease_class}
            
    return {"matched_disease": None, "disease_class": "Other / General"}
