"""Blockchain tracers for Bitcoin and Ethereum using free public APIs."""

import hashlib
import requests
import time
from typing import Optional


def _enable_system_trust_store() -> None:
    """Prefer the platform trust store when available."""
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:
        pass


_enable_system_trust_store()

# Bitcoin (no key)
BTC_BASE_URL = "https://blockstream.info/api"
BTC_FALLBACK_URL = "https://mempool.space/api"

# Ethereum (free public key on Ethplorer)
ETH_BASE_URL = "https://api.ethplorer.io"
ETH_API_KEY = "freekey"
ETH_FALLBACK_URL = "https://api.blockcypher.com/v1/eth/main"

REQUEST_DELAY = 0.35
MAX_OUTPUTS_TO_FOLLOW = 5

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class BitcoinTracer:
    """
    Core class: fetches Bitcoin blockchain data and traces fund flows
    hop by hop up to a configurable maximum depth.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BTC-Trail-Analyzer/1.0"})
        # Cache already-fetched transactions to reduce API calls
        self._tx_cache: dict = {}
        self._addr_cache: dict = {}

    # ─────────────────────────────────────────────
    # Input detection
    # ─────────────────────────────────────────────

    def detect_input_type(self, query: str) -> str:
        """
        Heuristic to decide if input is a wallet address or a transaction hash.
        - Bitcoin addresses: 25–34 chars, start with 1, 3, or bc1
        - TX hashes:         exactly 64 hex characters
        """
        query = query.strip()
        if len(query) == 64 and all(c in "0123456789abcdefABCDEF" for c in query):
            return "txid"
        if self.is_valid_bitcoin_address(query):
            return "address"
        return "unknown"

    def is_valid_bitcoin_address(self, address: str) -> bool:
        """Return True for a syntactically valid Bitcoin legacy or Bech32 address."""
        address = address.strip()
        if not address:
            return False

        lowered = address.lower()
        if lowered.startswith(("1", "3")):
            return self._is_valid_base58check_address(address)
        if lowered.startswith("bc1"):
            return self._is_valid_bech32_address(lowered, "bc")
        return False

    @staticmethod
    def _is_valid_base58check_address(address: str) -> bool:
        if not (26 <= len(address) <= 35):
            return False
        if any(char not in BASE58_ALPHABET for char in address):
            return False

        try:
            value = 0
            for char in address:
                value = value * 58 + BASE58_ALPHABET.index(char)

            payload = value.to_bytes(25, byteorder="big")
            checksum = payload[-4:]
            body = payload[:-4]
            expected = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
            return checksum == expected
        except Exception:
            return False

    @staticmethod
    def _bech32_polymod(values: list[int]) -> int:
        generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        checksum = 1
        for value in values:
            top = checksum >> 25
            checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
            for index in range(5):
                if (top >> index) & 1:
                    checksum ^= generator[index]
        return checksum

    @staticmethod
    def _bech32_hrp_expand(hrp: str) -> list[int]:
        return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]

    def _is_valid_bech32_address(self, address: str, expected_hrp: str) -> bool:
        if not (8 <= len(address) <= 90):
            return False
        if address.lower() != address and address.upper() != address:
            return False

        address = address.lower()
        separator = address.rfind("1")
        if separator < 1:
            return False

        hrp, data = address[:separator], address[separator + 1 :]
        if hrp != expected_hrp or len(data) < 6:
            return False
        if any(char not in BECH32_CHARSET for char in data):
            return False

        decoded = [BECH32_CHARSET.index(char) for char in data]
        polymod = self._bech32_polymod(self._bech32_hrp_expand(hrp) + decoded)
        return polymod in {1, 0x2BC830A3}

    # ─────────────────────────────────────────────
    # Raw API helpers
    # ─────────────────────────────────────────────

    def _get(self, url: str) -> Optional[dict]:
        """Perform a GET request with basic error handling and retry."""
        try:
            time.sleep(REQUEST_DELAY)
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            raise ConnectionError("Blockstream API timed out. Try again.")
        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"API HTTP error: {e}")
        except Exception as e:
            raise ConnectionError(f"Network error: {e}")

    def fetch_transaction(self, txid: str) -> Optional[dict]:
        """Fetch a single transaction by its hash from Blockstream."""
        if txid in self._tx_cache:
            return self._tx_cache[txid]
        data = None

        try:
            data = self._get(f"{BTC_BASE_URL}/tx/{txid}")
        except Exception:
            data = None

        if not data:
            try:
                data = self._get(f"{BTC_FALLBACK_URL}/tx/{txid}")
            except Exception:
                data = None

        if data:
            self._tx_cache[txid] = data
        return data

    def fetch_address_txs(self, address: str) -> list:
        """Fetch the most recent transactions for a Bitcoin address."""
        if address in self._addr_cache:
            return self._addr_cache[address]

        data = None
        provider_errors = []
        try:
            data = self._get(f"{BTC_BASE_URL}/address/{address}/txs")
        except Exception as e:
            provider_errors.append(f"blockstream: {e}")
            data = None

        if not isinstance(data, list):
            try:
                data = self._get(f"{BTC_FALLBACK_URL}/address/{address}/txs")
            except Exception as e:
                provider_errors.append(f"mempool: {e}")
                data = None

        if data is None and provider_errors:
            raise ConnectionError(
                "Bitcoin providers failed for this address. "
                "This can happen due to API restrictions/rate-limits. "
                f"Details: {' | '.join(provider_errors)}"
            )

        result = data if isinstance(data, list) else []
        self._addr_cache[address] = result
        return result

    def fetch_address_info(self, address: str) -> Optional[dict]:
        """Fetch balance and tx-count summary for an address."""
        data = None
        try:
            data = self._get(f"{BTC_BASE_URL}/address/{address}")
        except Exception:
            data = None

        if not data:
            try:
                data = self._get(f"{BTC_FALLBACK_URL}/address/{address}")
            except Exception:
                data = None

        return data

    # ─────────────────────────────────────────────
    # Transaction parsing helpers
    # ─────────────────────────────────────────────

    def parse_transaction(self, tx: dict) -> dict:
        """
        Normalize a raw Blockstream transaction into a clean dict:
        {
          txid, block_height, confirmed, fee_sat,
                    senders:  [{ address, value }],
                    receivers:[{ address, value }]
        }
        """
        txid = tx.get("txid", "unknown")
        status = tx.get("status", {})

        # ── Inputs (senders) ──
        senders = []
        for vin in tx.get("vin", []):
            prevout = vin.get("prevout", {})
            addr = prevout.get("scriptpubkey_address")
            value = prevout.get("value", 0)
            if addr:
                senders.append({
                    "address": addr,
                    "value": round(value / 1e8, 8)
                })

        # ── Outputs (receivers) ──
        receivers = []
        for vout in tx.get("vout", []):
            addr = vout.get("scriptpubkey_address")
            value = vout.get("value", 0)
            if addr:
                receivers.append({
                    "address": addr,
                    "value": round(value / 1e8, 8)
                })

        # Calculate fee
        total_in  = sum(s["value"] for s in senders)
        total_out = sum(r["value"] for r in receivers)
        fee_asset = round(max(0, total_in - total_out), 8)

        return {
            "txid":         txid,
            "block_height": status.get("block_height"),
            "confirmed":    status.get("confirmed", False),
            "fee":          fee_asset,
            "total_in":     total_in,
            "total_out":    total_out,
            "senders":      senders,
            "receivers":    receivers,
        }

    # ─────────────────────────────────────────────
    # Tracing entry points
    # ─────────────────────────────────────────────

    def trace_from_address(self, address: str, max_depth: int = 3) -> dict:
        """
        Start tracing from a wallet address.
        Fetches its latest transactions, then follows fund flow forward.
        """
        try:
            txs_raw = self.fetch_address_txs(address)
        except Exception as e:
            return {"error": str(e)}

        if not txs_raw:
            return {
                "error": (
                    f"No transactions found for address {address}. "
                    "Try another active address/sample; some legacy addresses "
                    "may be blocked or not returned by free providers in your region."
                )
            }

        # Seed: take first 3 transactions to keep response manageable
        seed_txs = txs_raw[:3]

        all_transactions = []
        visited_txids = set()
        visited_addresses = {address}

        for tx_raw in seed_txs:
            parsed = self.parse_transaction(tx_raw)
            all_transactions.append(parsed)
            visited_txids.add(parsed["txid"])

            # Recursively follow outgoing transactions
            self._trace_hops(
                parsed, all_transactions, visited_txids,
                visited_addresses, current_depth=1, max_depth=max_depth
            )

        return {
            "origin": address,
            "origin_type": "address",
            "asset_symbol": "BTC",
            "chain": "bitcoin",
            "transactions": all_transactions,
            "addresses_visited": list(visited_addresses),
            "max_depth_reached": max_depth,
        }

    def trace_from_transaction(self, txid: str, max_depth: int = 3) -> dict:
        """
        Start tracing from a specific transaction hash.
        Parses the TX and follows its outputs forward.
        """
        tx_raw = self.fetch_transaction(txid)
        if not tx_raw:
            return {"error": f"Transaction {txid} not found."}

        parsed = self.parse_transaction(tx_raw)
        all_transactions = [parsed]
        visited_txids = {txid}
        visited_addresses = set()

        for s in parsed["senders"]:
            visited_addresses.add(s["address"])
        for r in parsed["receivers"]:
            visited_addresses.add(r["address"])

        # Follow outputs recursively
        self._trace_hops(
            parsed, all_transactions, visited_txids,
            visited_addresses, current_depth=1, max_depth=max_depth
        )

        return {
            "origin": txid,
            "origin_type": "txid",
            "asset_symbol": "BTC",
            "chain": "bitcoin",
            "transactions": all_transactions,
            "addresses_visited": list(visited_addresses),
            "max_depth_reached": max_depth,
        }

    # ─────────────────────────────────────────────
    # Recursive hop tracer
    # ─────────────────────────────────────────────

    def _trace_hops(
        self,
        parent_tx: dict,
        all_transactions: list,
        visited_txids: set,
        visited_addresses: set,
        current_depth: int,
        max_depth: int,
    ):
        """
        BFS-style recursive follower:
        For each receiver address in parent_tx, fetch their subsequent
        transactions and recurse until max_depth is reached.
        """
        if current_depth >= max_depth:
            return

        # Limit how many output addresses we follow to prevent API flood
        receivers_to_follow = parent_tx["receivers"][:MAX_OUTPUTS_TO_FOLLOW]

        for receiver in receivers_to_follow:
            addr = receiver["address"]
            if addr in visited_addresses:
                continue
            visited_addresses.add(addr)

            try:
                addr_txs = self.fetch_address_txs(addr)
            except Exception:
                continue  # Skip if API fails for this address

            # Only follow the first outgoing transaction per address
            for tx_raw in addr_txs[:2]:
                txid = tx_raw.get("txid")
                if not txid or txid in visited_txids:
                    continue
                visited_txids.add(txid)

                try:
                    parsed = self.parse_transaction(tx_raw)
                except Exception:
                    continue

                all_transactions.append(parsed)

                # Recurse deeper
                self._trace_hops(
                    parsed, all_transactions, visited_txids,
                    visited_addresses, current_depth + 1, max_depth
                )


class EthereumTracer:
    """Fetch Ethereum transactions and trace outward account-to-account flow."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ETH-Trail-Analyzer/1.0"})
        self._tx_cache: dict = {}
        self._addr_cache: dict = {}

    def detect_input_type(self, query: str) -> str:
        """Detect Ethereum address vs transaction hash."""
        q = query.strip()
        if len(q) == 66 and q.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in q[2:]):
            return "txid"
        if len(q) == 42 and q.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in q[2:]):
            return "address"
        return "unknown"

    def _get(self, url: str) -> Optional[dict]:
        try:
            time.sleep(REQUEST_DELAY)
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            raise ConnectionError("Ethereum API timed out. Try again.")
        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"API HTTP error: {e}")
        except Exception as e:
            raise ConnectionError(f"Network error: {e}")

    @staticmethod
    def _normalize_eth_value(raw_value) -> float:
        """Ethplorer may return ETH or WEI-like values depending on endpoint/data."""
        try:
            value = float(raw_value or 0)
        except (TypeError, ValueError):
            return 0.0
        if value > 1e12:
            value = value / 1e18
        return round(value, 8)

    def fetch_transaction(self, txid: str) -> Optional[dict]:
        if txid in self._tx_cache:
            return self._tx_cache[txid]

        # Primary provider: Ethplorer
        try:
            data = self._get(f"{ETH_BASE_URL}/getTxInfo/{txid}?apiKey={ETH_API_KEY}")
            if data and isinstance(data, dict) and not data.get("error"):
                self._tx_cache[txid] = data
                return data
        except Exception:
            pass

        # Fallback provider: BlockCypher (free)
        try:
            fallback = self._get(f"{ETH_FALLBACK_URL}/txs/{txid}")
            if fallback and isinstance(fallback, dict) and fallback.get("hash"):
                self._tx_cache[txid] = fallback
                return fallback
        except Exception:
            pass

        return None

    def fetch_address_txs(self, address: str) -> list:
        if address in self._addr_cache:
            return self._addr_cache[address]

        txs = []

        # Primary provider: Ethplorer
        try:
            data = self._get(
                f"{ETH_BASE_URL}/getAddressTransactions/{address}?apiKey={ETH_API_KEY}&limit=25"
            )
            if isinstance(data, list):
                txs = data
        except Exception:
            pass

        # Fallback provider: BlockCypher
        if not txs:
            try:
                fallback = self._get(f"{ETH_FALLBACK_URL}/addrs/{address}/full?limit=25")
                if isinstance(fallback, dict):
                    txs = fallback.get("txs", []) or []
            except Exception:
                txs = []

        self._addr_cache[address] = txs
        return txs

    def parse_transaction(self, tx: dict) -> dict:
        txid = tx.get("hash") or tx.get("txid") or "unknown"

        # Ethplorer-style payload (from /getTxInfo and /getAddressTransactions)
        from_addr = tx.get("from")
        to_addr = tx.get("to")
        if from_addr or to_addr:
            value = self._normalize_eth_value(tx.get("value", 0))

            senders = [{"address": from_addr, "value": value}] if from_addr else []
            receivers = [{"address": to_addr, "value": value}] if to_addr else []

            fee = 0.0
            fee_field = tx.get("fee")
            if isinstance(fee_field, dict):
                fee = self._normalize_eth_value(fee_field.get("value", 0))
            elif fee_field is not None:
                fee = self._normalize_eth_value(fee_field)

            return {
                "txid": txid,
                "block_height": tx.get("blockNumber"),
                "confirmed": tx.get("confirmations", 0) > 0,
                "fee": fee,
                "total_in": value,
                "total_out": value,
                "senders": senders,
                "receivers": receivers,
            }

        # BlockCypher fallback-style payload
        senders = []
        for vin in tx.get("inputs", []):
            addrs = vin.get("addresses", [])
            if not addrs:
                continue
            vin_val = self._normalize_eth_value(vin.get("output_value") or vin.get("value") or 0)
            senders.append({"address": addrs[0], "value": vin_val})

        receivers = []
        for vout in tx.get("outputs", []):
            addrs = vout.get("addresses", [])
            if not addrs:
                continue
            vout_val = self._normalize_eth_value(vout.get("value", 0))
            receivers.append({"address": addrs[0], "value": vout_val})

        total_out = round(sum(r["value"] for r in receivers), 8)
        total_in = round(sum(s["value"] for s in senders), 8)
        fee = self._normalize_eth_value(tx.get("fees", 0))

        return {
            "txid": txid,
            "block_height": tx.get("block_height") or tx.get("blockNumber"),
            "confirmed": tx.get("confirmations", 0) > 0,
            "fee": fee,
            "total_in": total_in,
            "total_out": total_out,
            "senders": senders,
            "receivers": receivers,
        }

    def trace_from_address(self, address: str, max_depth: int = 3) -> dict:
        txs_raw = self.fetch_address_txs(address)
        if not txs_raw:
            return {"error": f"No transactions found for address {address}"}

        seed_txs = [tx for tx in txs_raw if tx.get("from", "").lower() == address.lower()][:3]
        if not seed_txs:
            seed_txs = txs_raw[:3]

        all_transactions = []
        visited_txids = set()
        visited_addresses = {address.lower()}

        for tx_raw in seed_txs:
            parsed = self.parse_transaction(tx_raw)
            if parsed["txid"] in visited_txids:
                continue
            all_transactions.append(parsed)
            visited_txids.add(parsed["txid"])

            self._trace_hops(
                parsed,
                all_transactions,
                visited_txids,
                visited_addresses,
                current_depth=1,
                max_depth=max_depth,
            )

        return {
            "origin": address,
            "origin_type": "address",
            "asset_symbol": "ETH",
            "chain": "ethereum",
            "transactions": all_transactions,
            "addresses_visited": list(visited_addresses),
            "max_depth_reached": max_depth,
        }

    def trace_from_transaction(self, txid: str, max_depth: int = 3) -> dict:
        tx_raw = self.fetch_transaction(txid)
        if not tx_raw:
            return {"error": f"Transaction {txid} not found."}

        parsed = self.parse_transaction(tx_raw)
        all_transactions = [parsed]
        visited_txids = {parsed["txid"]}
        visited_addresses = set()

        for s in parsed["senders"]:
            visited_addresses.add(s["address"].lower())
        for r in parsed["receivers"]:
            visited_addresses.add(r["address"].lower())

        self._trace_hops(
            parsed,
            all_transactions,
            visited_txids,
            visited_addresses,
            current_depth=1,
            max_depth=max_depth,
        )

        return {
            "origin": txid,
            "origin_type": "txid",
            "asset_symbol": "ETH",
            "chain": "ethereum",
            "transactions": all_transactions,
            "addresses_visited": list(visited_addresses),
            "max_depth_reached": max_depth,
        }

    def _trace_hops(
        self,
        parent_tx: dict,
        all_transactions: list,
        visited_txids: set,
        visited_addresses: set,
        current_depth: int,
        max_depth: int,
    ):
        if current_depth >= max_depth:
            return

        receivers_to_follow = parent_tx["receivers"][:MAX_OUTPUTS_TO_FOLLOW]

        for receiver in receivers_to_follow:
            addr = receiver["address"]
            if not addr:
                continue
            addr_lc = addr.lower()
            if addr_lc in visited_addresses:
                continue
            visited_addresses.add(addr_lc)

            try:
                addr_txs = self.fetch_address_txs(addr)
            except Exception:
                continue

            outgoing = [tx for tx in addr_txs if tx.get("from", "").lower() == addr_lc]

            for tx_raw in outgoing[:2]:
                txid = tx_raw.get("hash") or tx_raw.get("txid")
                if not txid or txid in visited_txids:
                    continue
                visited_txids.add(txid)

                try:
                    parsed = self.parse_transaction(tx_raw)
                except Exception:
                    continue

                all_transactions.append(parsed)

                self._trace_hops(
                    parsed,
                    all_transactions,
                    visited_txids,
                    visited_addresses,
                    current_depth + 1,
                    max_depth,
                )
