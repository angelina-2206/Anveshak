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
        try:
            cl = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(cl) if cl > 0 else b""
            return self.send_json_response({
                "status": "READ_BODY_OK",
                "bytes_read": len(raw_body),
                "preview": raw_body.decode('utf-8', errors='ignore')[:100]
            })
        except Exception as e:
            return self.send_error_response(f"Read body error: {e}", 500)


