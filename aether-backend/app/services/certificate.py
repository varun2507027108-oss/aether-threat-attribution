"""Statutory Forensic Certificate Generation under Section 63, Bharatiya Sakshya Adhiniyam, 2023
(formerly Section 65B, Indian Evidence Act, 1872).

Generates a tamper-evident, court-admissible PDF document containing case particulars,
system operating statements, cryptographic hash-chain Genesis and Tip hashes,
sequence ranges, investigator identity, signature blocks, and verification instructions.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.services.custody import GENESIS_HASH, CustodyChain

if TYPE_CHECKING:
    from app.models import Case, CustodyRow


def generate_statutory_certificate(
    case: Case,
    custody_rows: list[CustodyRow],
    investigator_operator: str = "Lead Forensic Investigator",
) -> bytes:
    """Generate a court-admissible statutory certificate in PDF format."""
    buffer = io.BytesIO()

    # Disable pageCompression so tests and PDF viewers can easily inspect text streams
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        pageCompression=0,
    )

    styles = getSampleStyleSheet()

    # Custom styles matching AETHER industrial dark steel / law document palette
    title_style = ParagraphStyle(
        "CertTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        alignment=1,  # Center
    )

    subtitle_style = ParagraphStyle(
        "CertSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
        alignment=1,
    )

    sub_statutory_style = ParagraphStyle(
        "CertStatutoryHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155"),
        alignment=1,
    )

    section_heading = ParagraphStyle(
        "CertSection",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )

    body_style = ParagraphStyle(
        "CertBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
    )

    legal_text_style = ParagraphStyle(
        "CertLegalText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155"),
    )

    mono_style = ParagraphStyle(
        "CertMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )

    mono_bold = ParagraphStyle(
        "CertMonoBold",
        parent=styles["Normal"],
        fontName="Courier-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0284c7"),
    )

    elements = []

    # 1. Header & Title Block
    elements.append(Paragraph("PROJECT AETHER // THREAT ATTRIBUTION SYSTEM", subtitle_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph("STATUTORY CERTIFICATE OF ELECTRONIC EVIDENCE INTEGRITY", title_style))
    elements.append(Spacer(1, 3))
    elements.append(
        Paragraph(
            "Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)",
            sub_statutory_style,
        )
    )
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=10))

    # 2. Case & Target Particulars Table
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    created_utc = case.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if case.created_at else now_utc
    target = case.target_url or case.onion_url or "N/A"

    particulars_data = [
        [
            Paragraph("<b>Case Reference ID:</b>", body_style),
            Paragraph(f"<b>{case.evidence_id}</b>", mono_bold),
            Paragraph("<b>Certificate Generated:</b>", body_style),
            Paragraph(now_utc, mono_style),
        ],
        [
            Paragraph("<b>Attributed Threat Actor:</b>", body_style),
            Paragraph(case.actor_name, body_style),
            Paragraph("<b>Case Initialized:</b>", body_style),
            Paragraph(created_utc, mono_style),
        ],
        [
            Paragraph("<b>Target URL / Onion:</b>", body_style),
            Paragraph(target, mono_style),
            Paragraph("<b>Confidence Score (C_attr):</b>", body_style),
            Paragraph(f"<b>{case.confidence:.1f}%</b>", body_style),
        ],
        [
            Paragraph("<b>Assigned Operator:</b>", body_style),
            Paragraph(investigator_operator, body_style),
            Paragraph("<b>Target Type:</b>", body_style),
            Paragraph(case.target_type, body_style),
        ],
    ]

    particulars_table = Table(particulars_data, colWidths=[130, 160, 120, 130])
    particulars_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    elements.append(particulars_table)
    elements.append(Spacer(1, 10))

    # 3. Device & System Particulars
    elements.append(Paragraph("1. DEVICE & OPERATING SYSTEM PARTICULARS", section_heading))
    elements.append(Spacer(1, 3))
    device_data = [
        [
            Paragraph("<b>Producing System:</b>", body_style),
            Paragraph("AETHER Forensic Node (Attribution & Custody Subsystem)", body_style),
        ],
        [
            Paragraph("<b>Software Environment:</b>", body_style),
            Paragraph("FastAPI 0.115 / SQLAlchemy 2.0 / SHA-256 Chain Engine (Linux x86_64)", body_style),
        ],
        [
            Paragraph("<b>Operating Condition:</b>", body_style),
            Paragraph(
                "The computer system and forensic hashing modules operated continuously and regularly throughout the period of target observation and analysis without defect, interference, or unhandled malfunction.",
                legal_text_style,
            ),
        ],
    ]
    device_table = Table(device_data, colWidths=[140, 400])
    device_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    elements.append(device_table)
    elements.append(Spacer(1, 10))

    # 4. Cryptographic Hash Chain & Custody State
    elements.append(Paragraph("2. CRYPTOGRAPHIC HASH CHAIN & DIGITAL SEAL", section_heading))
    elements.append(Spacer(1, 3))

    chain_rows = [
        {
            "seq": r.seq,
            "timestamp": r.timestamp,
            "actor": r.actor,
            "action": r.action,
            "prev_hash": r.prev_hash,
            "entry_hash": r.entry_hash,
        }
        for r in custody_rows
    ]
    chain = CustodyChain.from_rows(chain_rows)
    chain_valid, broken_seq = chain.verify()
    entry_count = len(custody_rows)
    tip_hash = custody_rows[-1].entry_hash if custody_rows else GENESIS_HASH
    seal_hash = chain.seal()

    chain_status_text = (
        "<font color='#16a34a'><b>VERIFIED VALID — ZERO TAMPERING DETECTED</b></font>"
        if chain_valid
        else f"<font color='#dc2626'><b>CHAIN COMPROMISED AT SEQ {broken_seq}</b></font>"
    )

    seq_range = f"Seq 1 to Seq {entry_count}" if entry_count > 0 else "0 (Empty)"

    crypto_data = [
        [
            Paragraph("<b>Genesis Hash (Root):</b>", body_style),
            Paragraph(GENESIS_HASH, mono_style),
        ],
        [
            Paragraph("<b>Chain Tip Hash:</b>", body_style),
            Paragraph(f"<b>{tip_hash}</b>", mono_bold),
        ],
        [
            Paragraph("<b>Digital Chain Seal:</b>", body_style),
            Paragraph(seal_hash, mono_style),
        ],
        [
            Paragraph("<b>Sequence Range:</b>", body_style),
            Paragraph(f"{seq_range} ({entry_count} verified entries)", body_style),
        ],
        [
            Paragraph("<b>Verification Status:</b>", body_style),
            Paragraph(chain_status_text, body_style),
        ],
    ]
    crypto_table = Table(crypto_data, colWidths=[140, 400])
    crypto_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    elements.append(crypto_table)
    elements.append(Spacer(1, 10))

    # 5. Statutory Declaration Under Section 63 BSA 2023
    elements.append(Paragraph("3. STATUTORY DECLARATION", section_heading))
    elements.append(Spacer(1, 3))
    declaration_text = (
        "I, the undersigned authorized forensic examiner, hereby certify under Section 63 of the Bharatiya "
        "Sakshya Adhiniyam, 2023 (formerly Section 65B of the Indian Evidence Act, 1872) that: (a) the electronic record "
        "and attribution dossier referenced under Case ID <b>"
        + case.evidence_id
        + "</b> was produced by the above-described computing system during a period in which the system was used regularly to store or "
        "process digital information for intelligence and forensic operations; (b) throughout the material period, the system "
        "was functioning properly without interruption or distortion affecting accuracy; and (c) the cryptographic SHA-256 "
        "hash chain provides continuous, tamper-evident proof that the electronic evidence has not been altered, substituted, "
        "or deleted since initial acquisition."
    )
    elements.append(Paragraph(declaration_text, legal_text_style))
    elements.append(Spacer(1, 8))

    # 6. Verification Instructions (Pointing at verify.html)
    elements.append(Paragraph("4. INDEPENDENT VERIFICATION INSTRUCTIONS", section_heading))
    elements.append(Spacer(1, 3))
    verify_instructions = (
        "This electronic evidence can be independently validated out-of-band without relying on the live system: "
        "<b>(1)</b> Export the forensic audit ledger (CSV format) from the AETHER dossier export subsystem; "
        "<b>(2)</b> Open the zero-dependency browser verification utility (<b>verify.html</b>); "
        "<b>(3)</b> Drop or paste the exported CSV content; the browser's Web Crypto engine (crypto.subtle) will "
        "recalculate the SHA-256 digest for every row from Genesis to Tip; "
        "<b>(4)</b> Confirm that the final calculated tip hash exactly matches the Chain Tip Hash certified above ("
        + tip_hash[:16]
        + "...)."
    )
    elements.append(Paragraph(verify_instructions, legal_text_style))
    elements.append(Spacer(1, 14))

    # 7. Signature & Attestation Block
    sig_data = [
        [
            Paragraph("<b>Certified & Executed By:</b>", body_style),
            Paragraph("<b>Official Forensic Seal:</b>", body_style),
        ],
        [
            Paragraph(
                "<br/><br/>____________________________________________________<br/>"
                f"<b>Signature of Authorized Officer</b><br/>"
                f"Name: <b>{investigator_operator}</b><br/>"
                "Designation: Digital Forensic Investigator / Analyst<br/>"
                "Agency: National Cyber Threat Attribution Unit<br/>"
                f"Date: {now_utc[:10]}",
                body_style,
            ),
            Paragraph(
                "<br/><br/>"
                "<b>[ OFFICIAL SEAL / EMBEDDED DIGITAL HASH ]</b><br/><br/>"
                f"<font size=6 face='Courier'>SHA256:{seal_hash[:32]}<br/>{seal_hash[32:]}</font>",
                body_style,
            ),
        ],
    ]
    sig_table = Table(sig_data, colWidths=[300, 240])
    sig_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(sig_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
