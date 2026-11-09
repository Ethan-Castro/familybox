# Filling forms on the box

An assistant can help fill out a form without ever seeing the real numbers. It tells the box which
field gets which detail, and the box puts the real value in itself.

## How it works

1. The assistant calls `list_family_forms` to see the forms and their fields.
2. It calls `fill_family_form(form, for_person, fields)`. Each field is either plain text, or a
   reference to a private detail, like `{{maya.ssn}}`, `{{dana.passport_number}}`,
   `{{maya.date_of_birth}}` or `{{family.insurance_member_id}}`.
3. The box looks each reference up, but only in files the person asking may read. A teen's assistant
   can't use a parent's SSN, and a parent's assistant can't use a teen's health record.
4. The box fills the PDF, keeps it in `runtime/forms/` (only the box's user can read it), and asks every
   person whose details are in it to approve.
5. The assistant gets back only what was filled, with references masked ("Maya's SSN ending 4322").
   That text goes through the same answer check as every other answer before it leaves.
6. Once everyone has approved, the PDF can be downloaded from the **Forms** page of the box's web page.

## Who can download the filled PDF

One of the people whose details are in it, and only someone who may read every file those details came
from. So the PDF never shows anyone something they couldn't already see on the box. If nobody fits (for
example a form mixing two people who can't see each other's files), the box says so and asks for the form
to be filled in two parts.

Filled forms are deleted after 7 days, when anyone denies, or when someone deletes them on the Forms page.

## Details a reference can use

`name`, `ssn`, `date_of_birth`, `passport_number`, `passport_expiration`, `medical_record_number`,
`allergies`, `conditions`, `medications`, `immunizations`, `employer`, `w2_wages`,
`w2_federal_tax_withheld`, `agi`, `insurance_plan`, `insurance_member_id`, `insurance_group_number`.

Use `{{<person>.<detail>}}` for files in `people/<person>/`, or `{{family.<detail>}}` for `shared/`.
A reference that isn't allowed and one that isn't there get the same answer, so references can't be used
to find out what is in someone else's files.

Typed-in text can't contain anything shaped like a Social Security, card or ID number. Those have to be
references, so the box knows whose they are and asks that person. This rule looks only at the shape of
the text, never at stored values, so a refusal never confirms a guess.

## Command line (on the box)

```
familybox forms list
familybox forms fill --as dana --for maya student_aid_info '{"student_ssn": "{{maya.ssn}}", "school_year": "2027-28"}'
familybox forms mine --as maya
familybox forms approve --as maya <form id>        # or deny
familybox forms download --as maya <form id> out.pdf
```

## The demo forms

`demo/forms/` holds two made-up practice forms, made by `uv run python scripts/make_demo_forms.py`:
a simplified "Student Aid Information" form and a "School Sports Medical Form". They are fictional and
are not real government or school forms. Any fillable PDF with text fields can be added there; an
optional `<name>.json` next to it adds plain-English labels and hints for the assistant.

## Known limits

- Only text fields are filled (no checkboxes or signatures).
- The last 4 digits of an SSN and the last 3 characters of long ID numbers are shown to the assistant,
  the same as the box's other placeholders.
- A form shows its title and field names to the assistant; the form templates themselves are not secret.
