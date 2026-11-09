"""Make the two FICTIONAL fillable PDF form templates in demo/forms/ (pypdf only, no other PDF library).

  uv run python scripts/make_demo_forms.py [out_dir]

Each form is a one-page PDF with text fields (AcroForm) plus a small JSON file with plain-English hints
that the assistant sees through list_family_forms. These are practice forms made up for the demo. They
are not real government or school forms.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from pypdf import PdfWriter
from pypdf.generic import (ArrayObject, BooleanObject, DecodedStreamObject, DictionaryObject, FloatObject,
                           NameObject, NumberObject, TextStringObject)

ROOT = Path(__file__).resolve().parents[1]

FORMS = {
    "student_aid_info": {
        "title": "Student Aid Information (practice form)",
        "description": "A made-up, simplified college aid form: the student's details and both parents' "
                       "SSNs and income. Not a real FAFSA.",
        "note": "FICTIONAL PRACTICE FORM. Not a real government form. Do not mail.",
        "sections": [
            ("Student", [
                ("student_name", "Student full name", "{{<student>.name}}"),
                ("student_ssn", "Student Social Security number", "{{<student>.ssn}}"),
                ("student_date_of_birth", "Student date of birth", "{{<student>.date_of_birth}}"),
                ("school_year", "School year applying for", "text, for example 2027-28"),
                ("student_email", "Student email", "text"),
            ]),
            ("Parent 1", [
                ("parent1_name", "Parent 1 full name", "{{<parent>.name}}"),
                ("parent1_ssn", "Parent 1 Social Security number", "{{<parent>.ssn}}"),
                ("parent1_wages", "Parent 1 wages (W-2 box 1)", "{{<parent>.w2_wages}}"),
            ]),
            ("Parent 2", [
                ("parent2_name", "Parent 2 full name", "{{<parent>.name}}"),
                ("parent2_ssn", "Parent 2 Social Security number", "{{<parent>.ssn}}"),
                ("parent2_wages", "Parent 2 wages (W-2 box 1)", "{{<parent>.w2_wages}}"),
            ]),
            ("Household", [
                ("household_agi", "Adjusted gross income from the last tax return", "{{<parent>.agi}}"),
                ("household_size", "Number of people in the household", "text"),
                ("signature_date", "Date signed", "text"),
            ]),
        ],
    },
    "sports_medical": {
        "title": "School Sports Medical Form (practice form)",
        "description": "A made-up school sports form: the athlete's health details, insurance and an "
                       "emergency contact. Health details can only be filled by the athlete themselves.",
        "note": "FICTIONAL PRACTICE FORM for a made-up school. Not a real medical form.",
        "sections": [
            ("Athlete", [
                ("athlete_name", "Athlete full name", "{{<athlete>.name}}"),
                ("athlete_date_of_birth", "Athlete date of birth", "{{<athlete>.date_of_birth}}"),
                ("sport", "Sport", "text"),
                ("grade", "Grade", "text"),
            ]),
            ("Health", [
                ("allergies", "Allergies", "{{<athlete>.allergies}}"),
                ("conditions", "Medical conditions", "{{<athlete>.conditions}}"),
                ("medications", "Medications", "{{<athlete>.medications}}"),
                ("medical_record_number", "Clinic medical record number", "{{<athlete>.medical_record_number}}"),
            ]),
            ("Insurance", [
                ("insurance_plan", "Insurance plan", "{{family.insurance_plan}}"),
                ("insurance_member_id", "Insurance member ID", "{{family.insurance_member_id}}"),
                ("insurance_group_number", "Insurance group number", "{{family.insurance_group_number}}"),
            ]),
            ("Emergency contact", [
                ("emergency_contact_name", "Emergency contact name", "{{<parent>.name}} or text"),
                ("emergency_contact_phone", "Emergency contact phone", "text"),
            ]),
        ],
    },
}


def _kinds(hint: str) -> list[str]:
    """Which kinds of detail a field takes, from the details its hint references. A field whose hint has no
    reference takes typed-in text only. The box refuses, say, an SSN reference in a name field."""
    from familybox.formfill import ALIASES, FIELDS
    keys = [ALIASES.get(k, k) for k in re.findall(r"\.([a-z0-9_]+)\}\}", hint)]
    return sorted({FIELDS[k].kind for k in keys if k in FIELDS})


def _pdf_text(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_form(slug: str, spec: dict, out_dir: Path) -> Path:
    w = PdfWriter()
    page = w.add_blank_page(612, 792)
    font = w._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"), NameObject("/Encoding"): NameObject("/WinAnsiEncoding")}))
    bold = w._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica-Bold"),
        NameObject("/Encoding"): NameObject("/WinAnsiEncoding")}))
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({
        NameObject("/F1"): font, NameObject("/F2"): bold, NameObject("/Helv"): font})})

    ops = [f"BT /F2 17 Tf 50 742 Td ({_pdf_text(spec['title'])}) Tj ET",
           f"BT /F1 9 Tf 50 726 Td ({_pdf_text(spec['note'])}) Tj ET"]
    fields, annots = ArrayObject(), ArrayObject()
    y = 700
    for section, rows in spec["sections"]:
        ops.append(f"BT /F2 12 Tf 50 {y} Td ({_pdf_text(section)}) Tj ET")
        y -= 22
        for name, label, _hint in rows:
            ops.append(f"BT /F1 10 Tf 60 {y + 5} Td ({_pdf_text(label)}) Tj ET")
            field = DictionaryObject({
                NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Widget"),
                NameObject("/FT"): NameObject("/Tx"), NameObject("/T"): TextStringObject(name),
                NameObject("/TU"): TextStringObject(label), NameObject("/F"): NumberObject(4),
                NameObject("/Rect"): ArrayObject([FloatObject(290), FloatObject(y), FloatObject(560),
                                                  FloatObject(y + 18)]),
                NameObject("/DA"): TextStringObject("/Helv 10 Tf 0 g"),
                NameObject("/MK"): DictionaryObject({NameObject("/BC"): ArrayObject(
                    [FloatObject(0.55), FloatObject(0.55), FloatObject(0.55)])}),
                NameObject("/P"): page.indirect_reference,
            })
            ref = w._add_object(field)
            fields.append(ref)
            annots.append(ref)
            y -= 24
        y -= 8
    stream = DecodedStreamObject()
    stream.set_data("\n".join(ops).encode("latin-1"))
    page[NameObject("/Contents")] = w._add_object(stream)
    page[NameObject("/Annots")] = annots
    w._root_object[NameObject("/AcroForm")] = DictionaryObject({
        NameObject("/Fields"): fields, NameObject("/NeedAppearances"): BooleanObject(True),
        NameObject("/DA"): TextStringObject("/Helv 10 Tf 0 g"),
        NameObject("/DR"): DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/Helv"): font})}),
    })
    w.add_metadata({"/Title": spec["title"], "/Subject": spec["description"], "/Producer": "familybox demo"})
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf = out_dir / f"{slug}.pdf"
    with pdf.open("wb") as f:
        w.write(f)
    hints = {"title": spec["title"], "description": spec["description"],
             "fields": {name: {"label": label, "hint": hint, "kinds": _kinds(hint)}
                        for _, rows in spec["sections"] for name, label, hint in rows}}
    (out_dir / f"{slug}.json").write_text(json.dumps(hints, indent=1) + "\n")
    return pdf


def main(argv: list[str]) -> int:
    out_dir = Path(argv[0]) if argv else ROOT / "demo" / "forms"
    for slug, spec in FORMS.items():
        print(f"wrote {make_form(slug, spec, out_dir)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
