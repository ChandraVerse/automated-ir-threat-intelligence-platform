# Report Templates

This directory contains PDF layout templates used by `generator.py` (ReportLab).

## Structure

Templates are implemented as Python ReportLab `Paragraph` and `Table` styles
defined inline in `generator.py`. If you need to customise the report layout:

1. Open `report-generator/generator.py`
2. Modify the `_build_styles()` method to change fonts, colours, and spacing
3. The NIST 800-61 section order is controlled by `_build_sections()`

## Output

Generated PDFs are saved to `report-generator/output/`:

```
report-generator/output/
  IR_Report_<alert_id>_<timestamp>.pdf
```

## Branding

To add a company logo, place `logo.png` in this directory and update
`generator.py` line referencing `LOGO_PATH`.
