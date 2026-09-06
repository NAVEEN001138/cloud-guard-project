"""
Generates the official Indian Patent Office (IPO) Form 2 Complete Specification document (.docx)
from PATENT_DRAFT_INDIA.md with embedded 300 DPI figures and formal patent styling.
"""

import os
import re
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._element.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def create_patent_docx():
    doc = docx.Document()

    # Standard Patent Margins (1 inch all around)
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        section.page_width = Inches(8.27)  # A4
        section.page_height = Inches(11.69) # A4

    # Base Normal Style
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(11.5)
    normal_style.font.color.rgb = RGBColor(0x11, 0x18, 0x27)
    normal_style.paragraph_format.line_spacing = 1.25
    normal_style.paragraph_format.space_after = Pt(6)

    # Official IPO Form 2 Header Box
    header_table = doc.add_table(rows=5, cols=1)
    header_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    header_table.autofit = False

    header_texts = [
        "FORM 2\nTHE PATENTS ACT, 1970 (39 of 1970)\n&\nTHE PATENTS RULES, 2003",
        "COMPLETE SPECIFICATION\n(See section 10 and rule 13)",
        "1. TITLE OF THE INVENTION:\nADAPTIVE RUNTIME SECURITY CONSTRAINT COMPILATION AND DECISION SYSTEM FOR AUTOMATED INFRASTRUCTURE RESPONSE",
        "2. APPLICANT(S) & INVENTOR(S):\n(a) Name: NAVEEN RAVI\n(b) Nationality: Indian\n(c) Address: India",
        "3. PREAMBLE TO THE DESCRIPTION:\nTHE FOLLOWING SPECIFICATION PARTICULARLY DESCRIBES THE INVENTION AND THE MANNER IN WHICH IT IS TO BE PERFORMED."
    ]

    for i, row in enumerate(header_table.rows):
        cell = row.cells[0]
        cell.width = Inches(6.27)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER if i < 2 or i == 4 else WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(4)
        run = p.add_run(header_texts[i])
        run.bold = True
        run.font.name = 'Times New Roman'
        run.font.size = Pt(12) if i < 2 else Pt(11)
        set_cell_background(cell, "F8FAFC" if i % 2 == 0 else "FFFFFF")

    doc.add_paragraph().paragraph_format.space_after = Pt(14)

    # Read PATENT_DRAFT_INDIA.md
    with open("PATENT_DRAFT_INDIA.md", "r", encoding="utf-8") as f:
        md_text = f.read()

    # Skip the top header since we just generated the formal IPO Form 2 table
    start_pos = md_text.find("## 4. FIELD OF THE INVENTION")
    if start_pos != -1:
        body_text = md_text[start_pos:]
    else:
        body_text = md_text

    lines = body_text.splitlines()
    in_table = False
    table_lines = []

    for line in lines:
        stripped = line.strip()

        # Handle Tables
        if stripped.startswith("|") and stripped.endswith("|"):
            in_table = True
            table_lines.append(stripped)
            continue
        elif in_table:
            # Process accumulated table
            if len(table_lines) >= 2:
                headers = [c.strip() for c in table_lines[0].strip("|").split("|")]
                # Skip separator line (row 1)
                data_rows = []
                for r in table_lines[2:]:
                    cols = [c.strip() for c in r.strip("|").split("|")]
                    if len(cols) == len(headers):
                        data_rows.append(cols)
                    else:
                        # Pad or trim
                        while len(cols) < len(headers):
                            cols.append("")
                        data_rows.append(cols[:len(headers)])

                doc_table = doc.add_table(rows=len(data_rows) + 1, cols=len(headers))
                doc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
                # Set headers
                for col_idx, h in enumerate(headers):
                    c = doc_table.cell(0, col_idx)
                    p = c.paragraphs[0]
                    p.paragraph_format.space_before = Pt(3)
                    p.paragraph_format.space_after = Pt(3)
                    r_run = p.add_run(re.sub(r'[*_#]', '', h))
                    r_run.bold = True
                    r_run.font.name = 'Times New Roman'
                    r_run.font.size = Pt(9.5)
                    set_cell_background(c, "E2E8F0")

                for row_idx, r_data in enumerate(data_rows):
                    for col_idx, val in enumerate(r_data):
                        c = doc_table.cell(row_idx + 1, col_idx)
                        p = c.paragraphs[0]
                        p.paragraph_format.space_before = Pt(2)
                        p.paragraph_format.space_after = Pt(2)
                        clean_val = re.sub(r'[*_`]', '', val)
                        r_run = p.add_run(clean_val)
                        r_run.font.name = 'Times New Roman'
                        r_run.font.size = Pt(9)
                        if row_idx % 2 == 1:
                            set_cell_background(c, "F8FAFC")

                doc.add_paragraph().paragraph_format.space_after = Pt(6)
            in_table = False
            table_lines = []

        if not stripped:
            continue

        # Headings
        if stripped.startswith("## "):
            h_text = stripped[3:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(h_text)
            run.bold = True
            run.font.name = 'Times New Roman'
            run.font.size = Pt(13.5)
            run.font.color.rgb = RGBColor(0x1E, 0x3A, 0x8A)

            # Embed Figure 1 under Drawings
            if "BRIEF DESCRIPTION OF THE DRAWINGS" in h_text.upper():
                pass

        elif stripped.startswith("### "):
            h_text = stripped[4:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(h_text)
            run.bold = True
            run.font.name = 'Times New Roman'
            run.font.size = Pt(12)
            run.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

        elif stripped.startswith("#### "):
            h_text = stripped[5:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(6)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(h_text)
            run.bold = True
            run.font.name = 'Times New Roman'
            run.font.size = Pt(11)

        elif stripped.startswith("---"):
            continue

        elif stripped.startswith("- ") or stripped.startswith("* "):
            bullet_text = stripped[2:].strip()
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(2)
            clean_text = re.sub(r'[*_`]', '', bullet_text)
            run = p.add_run(clean_text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(11)

        elif re.match(r'^\d+\.\s', stripped):
            num_match = re.match(r'^(\d+\.)\s*(.*)', stripped)
            prefix = num_match.group(1)
            rest = num_match.group(2)
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.left_indent = Inches(0.25)
            r_num = p.add_run(f"{prefix} ")
            r_num.bold = True
            r_num.font.name = 'Times New Roman'
            r_num.font.size = Pt(11)
            r_text = p.add_run(re.sub(r'[*_`]', '', rest))
            r_text.font.name = 'Times New Roman'
            r_text.font.size = Pt(11)

        else:
            # Standard Paragraph
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.25

            # Embed Drawings where described
            clean_line = re.sub(r'[*_`]', '', stripped)
            run = p.add_run(clean_line)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(11)

            if "FIG. 1 illustrates the overall 9-layer" in stripped and os.path.exists("architecture_diagram.png"):
                p_fig1 = doc.add_paragraph()
                p_fig1.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_fig1.paragraph_format.space_before = Pt(6)
                p_fig1.paragraph_format.space_after = Pt(6)
                p_fig1.add_run().add_picture("architecture_diagram.png", width=Inches(5.8))
                cap1 = doc.add_paragraph()
                cap1.alignment = WD_ALIGN_PARAGRAPH.CENTER
                c1_run = cap1.add_run("FIG. 1: Complete 9-Layer Runtime Security Architecture")
                c1_run.font.name = 'Times New Roman'
                c1_run.font.size = Pt(10)
                c1_run.bold = True

            elif "FIG. 2 illustrates the runtime constraint compilation pipeline" in stripped and os.path.exists("process_flow_diagram.png"):
                p_fig2 = doc.add_paragraph()
                p_fig2.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_fig2.paragraph_format.space_before = Pt(6)
                p_fig2.paragraph_format.space_after = Pt(6)
                p_fig2.add_run().add_picture("process_flow_diagram.png", width=Inches(5.8))
                cap2 = doc.add_paragraph()
                cap2.alignment = WD_ALIGN_PARAGRAPH.CENTER
                c2_run = cap2.add_run("FIG. 2: Runtime Security Constraint Compilation & Decision Pipeline")
                c2_run.font.name = 'Times New Roman'
                c2_run.font.size = Pt(10)
                c2_run.bold = True

    output_path = "FORM_2_INDIAN_PATENT_SPECIFICATION.docx"
    doc.save(output_path)
    print(f"Successfully generated: {output_path} ({os.path.getsize(output_path)} bytes)")

if __name__ == "__main__":
    create_patent_docx()
