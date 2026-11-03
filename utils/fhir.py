"""Ekspor rekam medis ke HL7 FHIR R4 (Bundle bertipe collection).

Ini ekspor FHIR generik untuk interoperabilitas, BUKAN profil khusus SATUSEHAT: integrasi SATUSEHAT memerlukan
onboarding, kredensial, dan profil Kemenkes yang berada di luar kode ini. Kode ICD-10 memakai sistem
http://hl7.org/fhir/sid/icd-10; tanda vital memakai LOINC.
"""
from __future__ import annotations

import re
import uuid

NS = uuid.UUID("5f0a2b4c-7d3e-4c11-9a77-2f6f1c1d8e01")
UCUM = "http://unitsofmeasure.org"
LOINC = "http://loinc.org"
ENC_CLASS = {"Rawat jalan": ("AMB", "ambulatory"), "IGD": ("EMER", "emergency"),
             "Rawat inap": ("IMP", "inpatient encounter"), "Radiologi": ("AMB", "ambulatory")}


def _id(*parts: str) -> str:
    return str(uuid.uuid5(NS, "|".join(parts)))


def _ref(rid: str) -> dict:
    return {"reference": f"urn:uuid:{rid}"}


def _vital(code: str, display: str, value, unit: str, ucum: str, base: dict) -> dict:
    return {**base, "resourceType": "Observation", "status": "final",
            "category": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/observation-category", "code": "vital-signs"}]}],
            "code": {"coding": [{"system": LOINC, "code": code, "display": display}]},
            "valueQuantity": {"value": value, "unit": unit, "system": UCUM, "code": ucum}}


def record_to_bundle(record: dict, record_id: str) -> dict:
    patient, doctor = record.get("patient", {}), record.get("doctor", {})
    visit, vitals = record.get("visit", {}), record.get("vitals", {})
    pid, did, eid = _id("patient", patient.get("address", "")), _id("practitioner", doctor.get("address", "")), _id("encounter", record_id)
    date = visit.get("date") or (record.get("created_at") or "")[:10] or None
    entries: list[dict] = []

    def add(res: dict) -> None:
        entries.append({"fullUrl": f"urn:uuid:{res['id']}", "resource": res})

    add({"resourceType": "Patient", "id": pid, "identifier": [{"system": "urn:SeMediChain:wallet", "value": patient.get("address", "")}],
         "name": [{"text": patient.get("name", "")}]})
    prac = {"resourceType": "Practitioner", "id": did, "name": [{"text": doctor.get("name", "")}],
            "identifier": [{"system": "urn:SeMediChain:wallet", "value": doctor.get("address", "")}]}
    if doctor.get("str"):
        prac["identifier"].append({"system": "urn:SeMediChain:str", "value": doctor["str"]})
    add(prac)
    code, display = ENC_CLASS.get(visit.get("type"), ("AMB", "ambulatory"))
    enc = {"resourceType": "Encounter", "id": eid, "status": "finished", "subject": _ref(pid),
           "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode", "code": code, "display": display},
           "participant": [{"individual": _ref(did)}]}
    if date:
        enc["period"] = {"start": date}
    if record.get("complaint"):
        enc["reasonCode"] = [{"text": record["complaint"]}]
    add(enc)

    base = {"subject": _ref(pid), "encounter": _ref(eid)}
    codes = record.get("icd10") or []
    clinical = {"coding": [{"system": "http://terminology.hl7.org/CodeSystem/condition-clinical", "code": "active"}]}
    for c in codes or [None]:
        if c is None and not record.get("diagnosis"):
            continue
        cond = {**base, "resourceType": "Condition", "id": _id("condition", record_id, c or "text"), "clinicalStatus": clinical,
                "code": {"text": record.get("diagnosis", "")}}
        if c:
            cond["code"]["coding"] = [{"system": "http://hl7.org/fhir/sid/icd-10", "code": c}]
        add(cond)
    for i, name in enumerate(record.get("allergies") or []):
        add({"resourceType": "AllergyIntolerance", "id": _id("allergy", record_id, str(i)), "patient": _ref(pid), "code": {"text": name},
             "clinicalStatus": {"coding": [{"system": "http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical", "code": "active"}]}})
    for i, m in enumerate(record.get("medications") or []):
        dose = " ".join(x for x in (m.get("dosis"), m.get("frekuensi"), m.get("durasi")) if x)
        add({**base, "resourceType": "MedicationRequest", "id": _id("medreq", record_id, str(i)), "status": "active", "intent": "order",
             "requester": _ref(did), "medicationCodeableConcept": {"text": m.get("nama", "")}, "dosageInstruction": [{"text": dose}] if dose else []})

    eff = {"effectiveDateTime": date} if date else {}
    obs_base = {**base, **eff}
    bp = re.fullmatch(r"\s*(\d{2,3})\s*/\s*(\d{2,3})\s*", str(vitals.get("bp") or ""))
    if bp:
        comp = lambda c, d, v: {"code": {"coding": [{"system": LOINC, "code": c, "display": d}]},   # noqa: E731
                                "valueQuantity": {"value": int(v), "unit": "mmHg", "system": UCUM, "code": "mm[Hg]"}}
        add({**obs_base, "resourceType": "Observation", "id": _id("obs", record_id, "bp"), "status": "final",
             "category": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/observation-category", "code": "vital-signs"}]}],
             "code": {"coding": [{"system": LOINC, "code": "85354-9", "display": "Blood pressure panel"}]},
             "component": [comp("8480-6", "Systolic blood pressure", bp.group(1)), comp("8462-4", "Diastolic blood pressure", bp.group(2))]})
    for key, code, disp, unit, ucum in [("temp", "8310-5", "Body temperature", "Cel", "Cel"),
                                        ("pulse", "8867-4", "Heart rate", "/min", "/min"),
                                        ("spo2", "59408-5", "Oxygen saturation by pulse oximetry", "%", "%")]:
        if vitals.get(key):
            add(_vital(code, disp, vitals[key], unit, ucum, {**obs_base, "id": _id("obs", record_id, key)}))

    bundle = {"resourceType": "Bundle", "id": _id("bundle", record_id), "type": "collection", "entry": entries}
    if record.get("created_at"):
        bundle["timestamp"] = record["created_at"]
    return bundle
