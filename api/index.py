import sys
import os
import json
import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Ensure backend directory is in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app.db.seed_data import get_seed_cases
from app.schemas.forensics import CaseDetail, AttachmentItem
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

# Global in-memory case database initialized with rich seed data
cases_db = get_seed_cases()

class handler(BaseHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def send_json_response(self, data, status_code=200):
        self.send_response(status_code)
        self.send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        
        if hasattr(data, "model_dump"):
            body_dict = data.model_dump()
        elif hasattr(data, "dict"):
            body_dict = data.dict()
        else:
            body_dict = data
            
        body = json.dumps(body_dict, default=str)
        self.wfile.write(body.encode('utf-8'))

    def send_error_response(self, message, status_code=400):
        self.send_json_response({"status": "ERROR", "detail": message}, status_code=status_code)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip('/')
        
        # Health check
        if path in ["/api/health", "/health", "/v1/health", "/api/v1/health"]:
            return self.send_json_response({"status": "HEALTHY", "engine": "TRACE-X Serverless Core"})

        # List all cases
        if path in ["/api/v1/cases", "/api/cases", "/cases"]:
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
            return self.send_json_response(summaries)

        # STIX export: GET /api/v1/cases/{case_id}/stix
        stix_match = re.match(r"^/api/(?:v1/)?cases/([^/]+)/stix$", path)
        if stix_match:
            case_id = stix_match.group(1).upper()
            if case_id in cases_db:
                bundle = ChainOfCustodyService.export_stix_bundle(cases_db[case_id])
                return self.send_json_response(bundle)
            return self.send_error_response(f"Case '{case_id}' not found", 404)

        # Get specific case: GET /api/v1/cases/{case_id}
        case_match = re.match(r"^/api/(?:v1/)?cases/([^/]+)$", path)
        if case_match:
            case_id = case_match.group(1).upper()
            if case_id in cases_db:
                return self.send_json_response(cases_db[case_id])
            return self.send_error_response(f"Case '{case_id}' not found", 404)

        # Default root handler
        return self.send_json_response({
            "status": "ONLINE",
            "system": "TRACE-X Cyber-Forensic Workstation API",
            "version": "1.0.0",
            "path": path
        })

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip('/')
        
        # Read request body safely
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""
        
        json_payload = {}
        if raw_body:
            try:
                json_payload = json.loads(raw_body.decode('utf-8'))
            except Exception:
                pass

        # 1. Ingest Email: POST /api/v1/cases/ingest
        if path in ["/api/v1/cases/ingest", "/api/cases/ingest", "/cases/ingest"]:
            eml_str = (
                json_payload.get("eml_content") or 
                json_payload.get("raw_text") or 
                json_payload.get("content") or ""
            )
            
            if eml_str:
                eml_bytes = eml_str.encode('utf-8')
            else:
                eml_bytes = raw_body

            if not eml_bytes:
                return self.send_error_response("Provide an .eml file, raw email text, or json with eml_content.", 400)

            try:
                parsed = EmailParserService.parse_raw_eml(eml_bytes)
                case_num = len(cases_db) + 207
                case_id = f"CASE-{case_num}"

                hops = HeaderTracerService.trace_hops(parsed["received_headers"])
                auth = HeaderTracerService.parse_auth_headers(parsed["raw_headers_dict"], parsed["received_spf"], parsed["auth_results"])

                identity = IdentityEngineService.analyze_identity(
                    from_str=parsed["from"],
                    reply_to=parsed["reply_to"],
                    return_path=parsed["return_path"],
                    auth_aligned=(auth.alignment == "ALIGNED")
                )
                social_signals = SocialEngEngineService.analyze_social_engineering(parsed["body_text"])
                urls = UrlTracerService.analyze_urls(parsed["urls"])

                from app.services.ipgeolocation_service import IpGeolocationService
                seed_key = parsed.get("subject", "") + parsed.get("from", "") + parsed.get("body_text", "")
                if hops:
                    geo_info = IpGeolocationService.geolocate_ip(hops[0].ip, seed_text=seed_key)
                else:
                    geo_info = IpGeolocationService.get_fallback_location(seed_key)

                geo_fin = GeoFinancialService.extract_geo_financial(
                    parsed["body_text"],
                    ip_geo=f"{geo_info['city']}, {geo_info['country']}",
                    ip_lat=geo_info['lat'],
                    ip_lng=geo_info['lng']
                )

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

                threat_score = ThreatScorerService.calculate_decomposed_score(
                    identity=identity,
                    auth=auth,
                    social_signals=social_signals,
                    urls=urls,
                    campaign_matches=campaigns
                )

                graph = GraphBuilderService.build_attack_graph(
                    case_id=case_id,
                    sender_email=identity.sender_email,
                    identity=identity,
                    hops=hops,
                    urls=urls,
                    geo_fin=geo_fin,
                    campaigns=campaigns
                )

                coc_event = ChainOfCustodyService.create_event(
                    actor="SOC Ingestion Engine",
                    role="SYSTEM",
                    action="EVIDENCE_UPLOAD",
                    artifact_id=f"EV-EML-{case_num}",
                    details=f"Ingested email artifact and reconstructed attack graph with classification '{classification.summary_label}'.",
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
                    summary=f"Automated forensic ingestion. Classified as {classification.summary_label}. Sender deception rating: {identity.deception_score:.0f}/100.",
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
                return self.send_json_response(new_case)
            except Exception as e:
                import traceback
                return self.send_error_response(f"Ingestion Error: {e}\n{traceback.format_exc()}", 500)

        # 2. Impact Lab Simulation: POST /api/v1/cases/{case_id}/impact-lab
        impact_match = re.match(r"^/api/(?:v1/)?cases/([^/]+)/impact-lab$", path)
        if impact_match:
            case_id = impact_match.group(1).upper()
            if case_id not in cases_db:
                return self.send_error_response(f"Case '{case_id}' not found", 404)

            params = parse_qs(parsed_url.query)
            remove_url = json_payload.get("remove_url", params.get("remove_url", ["false"])[0].lower() == "true")
            assume_spf_pass = json_payload.get("assume_spf_pass", params.get("assume_spf_pass", ["false"])[0].lower() == "true")
            disconnect_campaign = json_payload.get("disconnect_campaign", params.get("disconnect_campaign", ["false"])[0].lower() == "true")
            remove_reply_mismatch = json_payload.get("remove_reply_mismatch", params.get("remove_reply_mismatch", ["false"])[0].lower() == "true")

            sim_result = ImpactLabService.simulate_counterfactual(
                case=cases_db[case_id],
                remove_url=remove_url,
                assume_spf_pass=assume_spf_pass,
                disconnect_campaign=disconnect_campaign,
                remove_reply_mismatch=remove_reply_mismatch
            )
            return self.send_json_response(sim_result)

        # 3. Forensic RAG Copilot: POST /api/v1/cases/{case_id}/rag
        rag_match = re.match(r"^/api/(?:v1/)?cases/([^/]+)/rag$", path)
        if rag_match:
            case_id = rag_match.group(1).upper()
            if case_id not in cases_db:
                return self.send_error_response(f"Case '{case_id}' not found", 404)

            question = json_payload.get("question", "")
            if not question:
                return self.send_error_response("Missing question in payload", 400)

            ans = ForensicRagService.answer_question(case=cases_db[case_id], question=question)
            return self.send_json_response(ans)

        # 4. Attachment Sandbox Detonation: POST /api/v1/cases/{case_id}/sandbox/{attachment_id}/detonate
        sandbox_match = re.match(r"^/api/(?:v1/)?cases/([^/]+)/sandbox/([^/]+)/detonate$", path)
        if sandbox_match:
            case_id = sandbox_match.group(1).upper()
            attachment_id = sandbox_match.group(2)
            if case_id not in cases_db:
                return self.send_error_response(f"Case '{case_id}' not found", 404)

            case = cases_db[case_id]
            att = next((a for a in case.attachments if a.attachment_id == attachment_id), None)
            if not att:
                import hashlib
                att = AttachmentItem(
                    attachment_id=attachment_id,
                    filename=f"detonated_payload_{attachment_id}.bin",
                    mime_type="application/octet-stream",
                    size_bytes=512000,
                    sha256=hashlib.sha256(attachment_id.encode()).hexdigest(),
                    is_executable=True,
                    is_macro_enabled=False,
                    risk_level="HIGH"
                )

            report = SandboxService.detonate(att)
            return self.send_json_response(report)

        # 5. Blockchain Anchor: POST /api/v1/cases/{case_id}/blockchain/anchor
        anchor_match = re.match(r"^/api/(?:v1/)?cases/([^/]+)/blockchain/anchor$", path)
        if anchor_match:
            case_id = anchor_match.group(1).upper()
            if case_id not in cases_db:
                return self.send_error_response(f"Case '{case_id}' not found", 404)
            case = cases_db[case_id]
            anchor_record = BlockchainService.anchor_evidence(case_id, case.model_dump())
            return self.send_json_response(anchor_record)

        # 6. Blockchain Verify: POST /api/v1/cases/{case_id}/blockchain/verify
        verify_match = re.match(r"^/api/(?:v1/)?cases/([^/]+)/blockchain/verify$", path)
        if verify_match:
            case_id = verify_match.group(1).upper()
            if case_id not in cases_db:
                return self.send_error_response(f"Case '{case_id}' not found", 404)
            case = cases_db[case_id]
            evidence_to_verify = json_payload if json_payload else case.model_dump()
            verify_record = BlockchainService.verify_evidence(evidence_to_verify, case_id)
            return self.send_json_response(verify_record)

        return self.send_error_response(f"Endpoint '{path}' not found", 404)



