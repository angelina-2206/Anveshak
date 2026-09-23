import logging
import json
import hashlib
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    from eth_account import Account
except ImportError:
    Account = None

from app.core.config import settings

logger = logging.getLogger("uvicorn.error")

# In-memory registry of anchored evidence records
_anchored_evidence_registry: Dict[str, Dict[str, Any]] = {}

class BlockchainService:
    @staticmethod
    def compute_canonical_evidence_hash(evidence_data: Dict[str, Any]) -> str:
        """
        Creates a deterministic/canonical SHA-256 hash of finalized evidence.
        Sorts dictionary keys and uses compact separators so identical evidence
        always yields the exact same SHA-256 hex digest.
        """
        # Filter out transient / non-evidence fields
        cleaned_data = {
            k: v for k, v in evidence_data.items()
            if k not in ("chain_of_custody", "updated_at", "blockchain_proof", "ai_analysis", "created_at", "blockchain_anchor")
        }
        canonical_json = json.dumps(cleaned_data, sort_keys=True, separators=(',', ':'), default=str)
        return "0x" + hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

    @staticmethod
    def anchor_evidence(case_id_or_target: str, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Anchors an evidence package to the Polygon blockchain via Alchemy JSON-RPC.
        Creates a signed transaction containing the SHA-256 evidence_hash in its data field.
        Broadcasts raw transaction via eth_sendRawTransaction.
        Stores ONLY the SHA-256 evidence_hash + transaction metadata on-chain.
        Never exposes raw evidence, private keys, or credentials.
        """
        evidence_hash = BlockchainService.compute_canonical_evidence_hash(evidence_data)
        timestamp = datetime.now(timezone.utc).isoformat()
        
        has_rpc = bool(settings.ALCHEMY_RPC_URL and settings.ALCHEMY_RPC_URL.strip())
        has_key = bool(settings.BLOCKCHAIN_PRIVATE_KEY and settings.BLOCKCHAIN_PRIVATE_KEY.strip())

        if not has_rpc or not has_key or Account is None:
            logger.warning("[Blockchain-Polygon] Alchemy RPC, Private Key, or eth_account missing. Recording under MOCK_ANCHORED status.")
            mock_tx_hash = "0x" + hashlib.sha256(f"MOCK-TX-{case_id_or_target}-{evidence_hash}".encode('utf-8')).hexdigest()
            record = {
                "evidence_hash": evidence_hash,
                "tx_hash": mock_tx_hash,
                "network": "Polygon POS Mainnet (Simulated Mock)",
                "block_number": 48910245,
                "timestamp": timestamp,
                "anchoring_status": "MOCK_ANCHORED",
                "wallet_address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
                "onchain_verified": False
            }
            _anchored_evidence_registry[evidence_hash] = record
            _anchored_evidence_registry[case_id_or_target] = record
            _anchored_evidence_registry[mock_tx_hash] = record
            return record

        try:
            # 1. Initialize Account from Private Key
            account = Account.from_key(settings.BLOCKCHAIN_PRIVATE_KEY)
            wallet_address = account.address

            logger.info(f"[Blockchain-Polygon] Fetching transaction count & gas price for wallet {wallet_address[:8]}...")

            # 2. Query Nonce (eth_getTransactionCount)
            nonce_res = requests.post(
                settings.ALCHEMY_RPC_URL,
                json={"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount", "params": [wallet_address, "pending"]},
                timeout=8.0
            )
            nonce = 0
            if nonce_res.status_code == 200 and "result" in nonce_res.json():
                nonce = int(nonce_res.json()["result"], 16)

            # 3. Query Gas Price (eth_gasPrice)
            gas_res = requests.post(
                settings.ALCHEMY_RPC_URL,
                json={"jsonrpc": "2.0", "id": 2, "method": "eth_gasPrice", "params": []},
                timeout=8.0
            )
            gas_price = 30000000000  # Default 30 Gwei fallback
            if gas_res.status_code == 200 and "result" in gas_res.json():
                gas_price = int(gas_res.json()["result"], 16)

            # 4. Query Chain ID (eth_chainId)
            chain_res = requests.post(
                settings.ALCHEMY_RPC_URL,
                json={"jsonrpc": "2.0", "id": 3, "method": "eth_chainId", "params": []},
                timeout=8.0
            )
            chain_id = 137  # Polygon POS Mainnet
            if chain_res.status_code == 200 and "result" in chain_res.json():
                chain_id = int(chain_res.json()["result"], 16)

            # 5. Build EIP-155 Transaction with Evidence Hash payload
            hash_bytes = bytes.fromhex(evidence_hash[2:]) if evidence_hash.startswith("0x") else bytes.fromhex(evidence_hash)
            tx_dict = {
                "nonce": nonce,
                "gasPrice": gas_price,
                "gas": 100000,
                "to": wallet_address,  # Self-transaction anchoring evidence payload
                "value": 0,
                "data": hash_bytes,
                "chainId": chain_id
            }

            # 6. Sign Transaction
            signed_tx = Account.sign_transaction(tx_dict, settings.BLOCKCHAIN_PRIVATE_KEY)
            raw_tx_bytes = getattr(signed_tx, "raw_transaction", None) or getattr(signed_tx, "rawTransaction")
            raw_tx_hex = "0x" + raw_tx_bytes.hex() if isinstance(raw_tx_bytes, bytes) else raw_tx_bytes

            # 7. Broadcast Raw Transaction via eth_sendRawTransaction
            send_res = requests.post(
                settings.ALCHEMY_RPC_URL,
                json={"jsonrpc": "2.0", "id": 4, "method": "eth_sendRawTransaction", "params": [raw_tx_hex]},
                timeout=12.0
            )
            
            send_json = send_res.json()
            if send_res.status_code == 200 and "result" in send_json:
                real_tx_hash = send_json["result"]
                logger.info(f"[Blockchain-Polygon] Broadcast SUCCESS. Real Tx Hash: {real_tx_hash}")

                # Query latest block number
                block_res = requests.post(
                    settings.ALCHEMY_RPC_URL,
                    json={"jsonrpc": "2.0", "id": 5, "method": "eth_blockNumber", "params": []},
                    timeout=5.0
                )
                block_number = 48910245
                if block_res.status_code == 200 and "result" in block_res.json():
                    block_number = int(block_res.json()["result"], 16)

                record = {
                    "evidence_hash": evidence_hash,
                    "tx_hash": real_tx_hash,
                    "network": f"Polygon POS (ChainID: {chain_id})",
                    "block_number": block_number,
                    "timestamp": timestamp,
                    "anchoring_status": "POLYGON_ANCHORED",
                    "wallet_address": wallet_address,
                    "onchain_verified": True
                }
                _anchored_evidence_registry[evidence_hash] = record
                _anchored_evidence_registry[case_id_or_target] = record
                _anchored_evidence_registry[real_tx_hash] = record
                return record
            else:
                error_msg = send_json.get("error", {}).get("message", send_res.text)
                logger.error(f"[Blockchain-Polygon] eth_sendRawTransaction failed: {error_msg}")
                # Return record with RPC error explanation but fallback tx hash
                fallback_tx = "0x" + hashlib.sha256(f"RPC-FAIL-{evidence_hash}".encode('utf-8')).hexdigest()
                record = {
                    "evidence_hash": evidence_hash,
                    "tx_hash": fallback_tx,
                    "network": f"Polygon POS (ChainID: {chain_id})",
                    "block_number": 48910245,
                    "timestamp": timestamp,
                    "anchoring_status": "MOCK_ANCHORED",
                    "wallet_address": wallet_address,
                    "onchain_verified": False,
                    "rpc_notice": f"RPC broadcast rejected (insufficient MATIC or invalid key): {error_msg}"
                }
                _anchored_evidence_registry[evidence_hash] = record
                _anchored_evidence_registry[case_id_or_target] = record
                _anchored_evidence_registry[fallback_tx] = record
                return record

        except Exception as e:
            clean_e = str(e).replace(settings.BLOCKCHAIN_PRIVATE_KEY, "REDACTED_KEY") if settings.BLOCKCHAIN_PRIVATE_KEY else str(e)
            logger.error(f"[Blockchain-Polygon] Anchoring exception: {clean_e}")
            mock_tx_hash = "0x" + hashlib.sha256(f"MOCK-EXC-{case_id_or_target}-{evidence_hash}".encode('utf-8')).hexdigest()
            record = {
                "evidence_hash": evidence_hash,
                "tx_hash": mock_tx_hash,
                "network": "Polygon POS Mainnet (Fallback Mock)",
                "block_number": 48910245,
                "timestamp": timestamp,
                "anchoring_status": "MOCK_ANCHORED",
                "wallet_address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
                "onchain_verified": False
            }
            _anchored_evidence_registry[evidence_hash] = record
            _anchored_evidence_registry[case_id_or_target] = record
            _anchored_evidence_registry[mock_tx_hash] = record
            return record

    @staticmethod
    def verify_evidence(
        evidence_data: Dict[str, Any],
        case_id_or_target: str = "",
        tx_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verifies evidence integrity against on-chain transaction data.
        1. Recomputes current canonical SHA-256 evidence_hash.
        2. If Alchemy RPC is available and tx_hash is provided/anchored:
           Queries Polygon node via eth_getTransactionByHash to inspect the actual on-chain transaction input data.
        3. Returns status: 'VALID' or 'TAMPERED'.
        """
        current_hash = BlockchainService.compute_canonical_evidence_hash(evidence_data)
        
        anchor_record = (
            _anchored_evidence_registry.get(current_hash) or
            _anchored_evidence_registry.get(case_id_or_target) or
            (_anchored_evidence_registry.get(tx_hash) if tx_hash else None)
        )

        target_tx_hash = tx_hash or (anchor_record.get("tx_hash") if anchor_record else None)

        # On-Chain RPC Verification (if Alchemy RPC is configured and transaction hash exists)
        if settings.ALCHEMY_RPC_URL and target_tx_hash and not target_tx_hash.startswith("0xMOCK"):
            try:
                res = requests.post(
                    settings.ALCHEMY_RPC_URL,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionByHash", "params": [target_tx_hash]},
                    timeout=8.0
                )
                if res.status_code == 200 and "result" in res.json() and res.json()["result"]:
                    tx_data = res.json()["result"]
                    onchain_input = tx_data.get("input", "")  # Hex encoded input data
                    
                    # Convert onchain_input hex to standard 0x sha256 string
                    if onchain_input.startswith("0x"):
                        onchain_hash = "0x" + onchain_input[2:]
                    else:
                        onchain_hash = "0x" + onchain_input

                    match = (current_hash.lower() == onchain_hash.lower())
                    return {
                        "status": "VALID" if match else "TAMPERED",
                        "current_hash": current_hash,
                        "anchored_hash": onchain_hash,
                        "match": match,
                        "onchain_verified": True,
                        "tx_hash": target_tx_hash,
                        "block_number": int(tx_data.get("blockNumber", "0x0"), 16) if tx_data.get("blockNumber") else None,
                        "anchoring_details": anchor_record
                    }
            except Exception as e:
                logger.warning(f"[Blockchain-Polygon] On-chain verification RPC query fallback: {e}")

        # Local / Mock registry verification fallback
        if not anchor_record:
            return {
                "status": "UNANCHORED",
                "current_hash": current_hash,
                "anchored_hash": None,
                "match": False,
                "message": "No on-chain anchor record found for this evidence."
            }

        anchored_hash = anchor_record["evidence_hash"]
        match = (current_hash == anchored_hash)
        
        return {
            "status": "VALID" if match else "TAMPERED",
            "current_hash": current_hash,
            "anchored_hash": anchored_hash,
            "match": match,
            "onchain_verified": anchor_record.get("onchain_verified", False),
            "tx_hash": target_tx_hash,
            "anchoring_details": anchor_record
        }

    @staticmethod
    def anchor_merkle_root(case_id: str, merkle_root: str) -> Optional[str]:
        """
        Backward-compatible helper for anchoring Merkle roots.
        """
        record = BlockchainService.anchor_evidence(case_id, {"case_id": case_id, "merkle_root": merkle_root})
        return record.get("tx_hash")
