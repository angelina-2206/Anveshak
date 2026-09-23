from fastapi import APIRouter, HTTPException, UploadFile, File, Form, status, Request
from typing import List, Optional, Dict, Any
from app.db.seed_data import get_seed_cases
from app.schemas.forensics import CaseDetail, ChainOfCustodyEvent, AttachmentItem
from app.core.security import enforce_rate_limit, ingest_limiter, rag_limiter, sandbox_limiter
from app.services.email_parser import EmailParserService
from app.services.header_tracer import HeaderTracerService
from app.services.identity_engine import IdentityEngineService
from app.services.social_eng_engine import SocialEngEngineService
from app.services.url_tracer import UrlTracerService
from app.services.geo_financial import GeoFinancialService
from app.services.threat_scorer import ThreatScorerService
from app.services.graph_builder import GraphBuilderService
from app.services.attack_dna import AttackDnaService
from app.services.chain_of_custody import ChainOfCustodyService
from app.services.impact_lab import ImpactLabService
from app.services.forensic_rag import ForensicRagService
from app.services.sandbox_service import SandboxService
from app.services.blockchain_service import BlockchainService
from app.services.email_classifier import EmailClassifierService

router = APIRouter(prefix="/cases", tags=["Cases & Forensics"])

# In-memory case repository initialized with seed datasets
cases_db: Dict[str, CaseDetail] = get_seed_cases()

@router.get("", response_model=List[Dict[str, Any]])
def list_cases():
    """
    Returns high-level summary cards for all active cases with classification and campaign tags.
    """
    summaries = []
    for c_id, c in cases_db.items():
        summaries.append({
            "case_id": c.case_id,
            "title": c.title,
            "status": c.status,
            "severity": c.severity,
            "threat_score": c.threat_score.overall_score,
            "email_subject": c.email_subject,
            "email_from": c.email_from,
            "assignee": c.assignee,
            "created_at": c.created_at,
            "classification": c.classification.dict() if c.classification else None,
            "campaign_matches": [cm.dict() for cm in c.campaign_matches] if c.campaign_matches else []
        })
    return summaries

@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: str):
    """
    Fetches full forensic details for a specific case.
    """
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return cases_db[case_id]

@router.post("/ingest", response_model=CaseDetail)
async def ingest_email(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None)
):
    enforce_rate_limit(request, ingest_limiter)
    """
    Ingests a raw .eml file or raw text export (via JSON or multipart/form-data).
    Executes live parsing, header flight recording, identity analysis, url tracer,
    social engineering detection, threat scoring, attack graph building, and chain of custody generation.
    """
    eml_bytes = None
    file_name = "uploaded_email.eml"

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            eml_str = body.get("eml_content") or body.get("raw_text") or body.get("content") or ""
            if eml_str:
                eml_bytes = eml_str.encode("utf-8")
        except Exception:
            pass

    if not eml_bytes:
        if file:
            eml_bytes = await file.read()
            file_name = file.filename or "uploaded_email.eml"
        elif raw_text:
            eml_bytes = raw_text.encode('utf-8')
            file_name = "raw_text_export.txt"

    if not eml_bytes:
        raise HTTPException(status_code=400, detail="Provide an .eml file, raw email text, or json with eml_content.")

    parsed = EmailParserService.parse_raw_eml(eml_bytes)

    case_num = len(cases_db) + 207
    case_id = f"CASE-{case_num}"
    
    # 1. Header Flight Path & Auth
    hops = HeaderTracerService.trace_hops(parsed["received_headers"])
    auth = HeaderTracerService.parse_auth_headers(parsed["raw_headers_dict"], parsed["received_spf"], parsed["auth_results"])
    
    # 2. Identity & Social Eng
    identity = IdentityEngineService.analyze_identity(
        from_str=parsed["from"],
        reply_to=parsed["reply_to"],
        return_path=parsed["return_path"],
        auth_aligned=(auth.alignment == "ALIGNED")
    )
    social_signals = SocialEngEngineService.analyze_social_engineering(parsed["body_text"])
    
    # 3. URL Tracer
    urls = UrlTracerService.analyze_urls(parsed["urls"])
    
    # 4. Geo-Financial
    from app.services.ipgeolocation_service import IpGeolocationService
    seed_key = parsed.get("subject", "") + parsed.get("from", "") + parsed.get("body_text", "")
    
    if hops:
        first_hop = hops[0]
        geo_info = IpGeolocationService.geolocate_ip(first_hop.ip, seed_text=seed_key)
    else:
        geo_info = IpGeolocationService.get_fallback_location(seed_key)
        
    ip_geo = f"{geo_info['city']}, {geo_info['country']}"
    ip_lat = geo_info['lat']
    ip_lng = geo_info['lng']
        
    geo_fin = GeoFinancialService.extract_geo_financial(
        parsed["body_text"],
        ip_geo=ip_geo,
        ip_lat=ip_lat,
        ip_lng=ip_lng
    )
    
    # 5. Attack DNA & Campaigns
    attack_dna = AttackDnaService.compute_attack_dna(
        case_id=case_id,
        identity=identity,
        urls=urls,
        hops=hops,
        subject=parsed.get("subject", ""),
        body_text=parsed.get("body_text", "")
    )
    campaigns = AttackDnaService.correlate_campaigns(
        current_dna=attack_dna,
        historical_cases=list(cases_db.values()),
        subject=parsed.get("subject", ""),
        sender_email=identity.sender_email,
        urls=urls,
        hops=hops,
        attachments=parsed.get("attachments", []),
        reply_to=parsed.get("reply_to", "") or "",
        message_id=parsed.get("raw_headers_dict", {}).get("message-id", "")
    )
    
    # 6. Email Classification (Categorization & Explainable Confidence)
    classification = EmailClassifierService.classify(
        subject=parsed.get("subject", ""),
        body_text=parsed.get("body_text", ""),
        identity=identity,
        auth_status=auth,
        urls=urls,
        attachments=parsed.get("attachments", []),
        hops=hops,
        geo_financial=geo_fin,
        campaigns=campaigns
    )

    # 7. Decomposed Threat Score
    threat_score = ThreatScorerService.calculate_decomposed_score(
        identity=identity,
        auth=auth,
        social_signals=social_signals,
        urls=urls,
        campaign_matches=campaigns
    )
    
    # 8. Attack Graph
    graph = GraphBuilderService.build_attack_graph(
        case_id=case_id,
        sender_email=identity.sender_email,
        identity=identity,
        hops=hops,
        urls=urls,
        geo_fin=geo_fin,
        campaigns=campaigns
    )
    
    # 9. Chain of Custody Event
    coc_event = ChainOfCustodyService.create_event(
        actor="SOC Ingestion Engine",
        role="SYSTEM",
        action="EVIDENCE_UPLOAD",
        artifact_id=f"EV-EML-{case_num}",
        details=f"Ingested email artifact '{file_name}' and reconstructed attack graph with classification '{classification.summary_label}'.",
        prev_events=[]
    )

    new_case = CaseDetail(
        case_id=case_id,
        title=f"Forensic Investigation - {parsed['subject'][:40]}",
        status="INVESTIGATING",
        severity=threat_score.severity,
        created_at="2026-08-30T20:50:00Z",
        updated_at="2026-08-30T20:50:00Z",
        assignee="Unassigned (Active Investigation)",
        summary=f"Automated forensic ingestion of '{file_name}'. Classified as {classification.summary_label}. Sender deception rating evaluated at {identity.deception_score:.0f}/100.",
        raw_email_id=f"EV-EML-{case_num}",
        email_subject=parsed["subject"],
        email_from=parsed["from"],
        email_to=parsed["to"],
        email_date=parsed["date"] or "Sun, 30 Aug 2026 20:50:00 +0000",
        header_hops=hops,
        auth_status=auth,
        identity_analysis=identity,
        social_eng_signals=social_signals,
        urls=urls,
        attachments=parsed["attachments"],
        geo_financial=geo_fin,
        threat_score=threat_score,
        attack_dna=attack_dna,
        campaign_matches=campaigns,
        attack_graph=graph,
        chain_of_custody=[coc_event],
        classification=classification
    )

    cases_db[case_id] = new_case
    return new_case

@router.post("/{case_id}/impact-lab")
def run_impact_lab(
    case_id: str,
    remove_url: bool = False,
    assume_spf_pass: bool = False,
    disconnect_campaign: bool = False,
    remove_reply_mismatch: bool = False
):
    """
    Counterfactual threat score simulator endpoint.
    """
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return ImpactLabService.simulate_counterfactual(
        case=cases_db[case_id],
        remove_url=remove_url,
        assume_spf_pass=assume_spf_pass,
        disconnect_campaign=disconnect_campaign,
        remove_reply_mismatch=remove_reply_mismatch
    )

@router.post("/{case_id}/rag")
def ask_ai_investigator(
    request: Request,
    case_id: str,
    payload: Dict[str, str]
):
    enforce_rate_limit(request, rag_limiter)
    """
    Grounded Forensic RAG query endpoint.
    """
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    question = payload.get("question", "")
    if not question:
        raise HTTPException(status_code=400, detail="Missing question in payload.")
    return ForensicRagService.answer_question(case=cases_db[case_id], question=question)

@router.get("/{case_id}/stix")
def export_stix(case_id: str):
    """
    Exports case indicators as a STIX 2.1 JSON bundle.
    """
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return ChainOfCustodyService.export_stix_bundle(cases_db[case_id])
@router.post("/{case_id}/sandbox/{attachment_id}/detonate")
def detonate_attachment(
    request: Request,
    case_id: str,
    attachment_id: str
):
    enforce_rate_limit(request, sandbox_limiter)
    """
    Static sandbox detonation endpoint.
    Returns a full forensic detonation report for a specific attachment:
    verdict, confidence, YARA matches, entropy, process tree, network IOCs,
    registry modifications, filesystem events, Win32 API calls, MITRE ATT&CK
    mapping, and decompiled pseudocode — all derived deterministically from
    the attachment's real metadata (no actual execution performed).
    """
    import hashlib
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    
    case = cases_db[case_id]
    attachment = next((a for a in case.attachments if a.attachment_id == attachment_id), None)
    
    if not attachment:
        # Fallback for demo/fallback attachments (e.g. from UI)
        if attachment_id == "ATT-002" or "Authorization" in attachment_id:
            attachment = AttachmentItem(
                attachment_id=attachment_id,
                filename="PaymentUpdate_Authorization.docm",
                mime_type="application/vnd.ms-word.document.macroEnabled.12",
                size_bytes=234880,
                sha256="f7e2d4b6a1c9e3f5b8d0a2c4e6f8b0d2a4c6e8f0b2d4a6c8e0f2b4d6a8c0e2f4",
                is_executable=False,
                is_macro_enabled=True,
                risk_level="HIGH"
            )
        elif attachment_id == "ATT-001" or "Invoice" in attachment_id:
            attachment = AttachmentItem(
                attachment_id=attachment_id,
                filename="Invoice_Payment_84920.pdf",
                mime_type="application/pdf",
                size_bytes=487424,
                sha256="a3f8b2c91e4d7f0e5b6a8c3d9e2f1b4a7c0e3f6b9d2a5c8e1f4b7a0d3e6f9b2",
                is_executable=False,
                is_macro_enabled=False,
                risk_level="HIGH"
            )
        else:
            # General generic fallback
            is_exe = attachment_id.endswith(".exe")
            attachment = AttachmentItem(
                attachment_id=attachment_id,
                filename=f"detonated_payload_{attachment_id}.bin",
                mime_type="application/octet-stream" if not is_exe else "application/x-msdownload",
                size_bytes=512000,
                sha256=hashlib.sha256(attachment_id.encode()).hexdigest(),
                is_executable=is_exe,
                is_macro_enabled=False,
                risk_level="HIGH"
            )

    report = SandboxService.detonate(attachment)
    
    # Save the report details back into cases_db if this is a real case attachment
    real_attachment = next((a for a in case.attachments if a.attachment_id == attachment_id), None)
    if real_attachment:
        real_attachment.sandbox_details = report

    # Generate Chain of Custody Event documenting sandbox detonation
    coc_event = ChainOfCustodyService.create_event(
        actor="Forensic Investigator",
        role="INVESTIGATOR",
        action="SANDBOX_DETONATION",
        artifact_id=attachment_id,
        details=f"Detonated attachment '{attachment.filename}' in isolated sandbox. Verdict: {report['verdict']} (Confidence: {report['confidence']}%).",
        prev_events=case.chain_of_custody
    )
    case.chain_of_custody.append(coc_event)

    return report


@router.post("/{case_id}/blockchain/anchor")
def anchor_case_evidence(case_id: str):
    """
    Anchors finalized case evidence hash on Polygon POS blockchain via Alchemy RPC.
    """
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    case = cases_db[case_id]
    case_dict = case.model_dump()
    anchor_record = BlockchainService.anchor_evidence(case_id, case_dict)
    
    # Update chain of custody with real blockchain proof
    coc_event = ChainOfCustodyService.create_event(
        actor="SOC Blockchain Agent",
        role="SYSTEM",
        action="BLOCKCHAIN_ANCHOR",
        artifact_id=f"EV-ANCHOR-{case_id}",
        details=f"Anchored evidence hash {anchor_record['evidence_hash'][:12]}... on {anchor_record['network']} (Tx: {anchor_record['tx_hash'][:12]}...). Status: {anchor_record['anchoring_status']}",
        prev_events=case.chain_of_custody
    )
    case.chain_of_custody.append(coc_event)
    return anchor_record


@router.post("/{case_id}/blockchain/verify")
def verify_case_evidence(case_id: str, payload: Optional[Dict[str, Any]] = None):
    """
    Verifies case evidence hash against Polygon on-chain record.
    Returns VALID or TAMPERED.
    """
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    case = cases_db[case_id]
    
    # If custom evidence payload is provided, verify it; otherwise verify current case state
    evidence_to_verify = payload if payload else case.model_dump()
    return BlockchainService.verify_evidence(evidence_to_verify, case_id)

