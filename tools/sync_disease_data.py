import pandas as pd
import csv
import io
import re

def clean_and_sync_dataset(input_path, output_path):
    """
    Membersihkan dataset penyakit yang tidak beraturan menjadi format CSV standar.
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Memperbaiki masalah pemisah yang hilang antara baris (Disease ID muncul di tengah baris)
    # Pattern: ID penyakit (misal C0012345) biasanya diikuti oleh karakter kapital
    # Kita akan melakukan split berdasarkan pola ID (C diikuti 7 digit)
    rows = []
    
    # regex untuk menangkap Disease ID
    pattern = re.compile(r'(C\d{7})')
    parts = pattern.split(content)
    
    # Bagian pertama adalah header/noise, abaikan
    # Setiap 2 bagian adalah ID dan detailnya
    for i in range(1, len(parts), 2):
        disease_id = parts[i]
        rest = parts[i+1].strip(',')
        
        # Split sisa string menjadi Name dan Class
        # Data biasanya dipisahkan koma, namun nama penyakit bisa ada koma dalam kutip
        # Menggunakan regex sederhana untuk memisahkan Name dan Class berdasarkan koma terakhir
        split_match = re.search(r'(.*),(.*)', rest)
        if split_match:
            name = split_match.group(1).strip('" ')
            class_name = split_match.group(2).strip()
            rows.append({"Disease ID": disease_id, "Disease Name": name, "Disease Class": class_name})

    # Save to clean CSV
    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)
    print(f"Dataset disinkronisasi ke: {output_path}")
    print(f"Total baris: {len(df)}")

if __name__ == "__main__":
    clean_and_sync_dataset("data/D-DoPathways_diseaseclasses.csv", "data/disease_classes_cleaned.csv")
