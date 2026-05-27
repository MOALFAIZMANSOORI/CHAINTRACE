"""
graph_builder.py
─────────────────────────────────────────────────────────────────────────────
Converts parsed transaction data into:
  1. A node/edge graph structure (for D3.js visualization)
  2. Suspicious pattern flags
  3. Probable end-receiver identification

Nodes = wallet addresses
Edges = transactions (with asset amount as weight)
─────────────────────────────────────────────────────────────────────────────
"""

import networkx as nx
from collections import defaultdict


class GraphBuilder:
    """
    Builds a directed transaction graph and performs forensic analysis.
    """

    # ─────────────────────────────────────────────
    # Graph construction
    # ─────────────────────────────────────────────

    def build_graph(self, trace_result: dict) -> dict:
        """
        Build a directed NetworkX graph and export it as a JSON-serializable
        dict with `nodes` and `edges` arrays suitable for D3.js rendering.

        Node types:
          - 'origin'       → the starting wallet / transaction
          - 'intermediate' → passes funds along
          - 'receiver'     → appears at the end (no further outgoing TXs seen)
        """
        G = nx.DiGraph()

        transactions   = trace_result.get("transactions", [])
        origin         = trace_result.get("origin", "")
        origin_type    = trace_result.get("origin_type", "")

        # Count outgoing transactions per address to classify node type later
        outgoing_count: dict = defaultdict(int)
        incoming_count: dict = defaultdict(int)

        # Track total asset received per address
        total_received: dict = defaultdict(float)
        total_sent:     dict = defaultdict(float)

        # ── Add nodes and edges from each parsed transaction ──
        for tx in transactions:
            txid      = tx["txid"]
            senders   = tx["senders"]
            receivers = tx["receivers"]

            for sender in senders:
                addr = sender["address"]
                G.add_node(addr, node_type="intermediate")
                outgoing_count[addr] += 1
                total_sent[addr] += sender["value"]

            for receiver in receivers:
                addr = receiver["address"]
                G.add_node(addr, node_type="intermediate")
                incoming_count[addr] += 1
                total_received[addr] += receiver["value"]

                # Add an edge from each sender → receiver for this transaction
                for sender in senders:
                    sender_addr = sender["address"]
                    if G.has_edge(sender_addr, addr):
                        # Accumulate value on repeated edges
                        G[sender_addr][addr]["value"] += receiver["value"]
                        G[sender_addr][addr]["tx_count"]  += 1
                    else:
                        G.add_edge(
                            sender_addr, addr,
                            txid      = txid,
                            value     = receiver["value"],
                            tx_count  = 1,
                        )

        # ── Mark the origin node ──
        if origin_type == "address" and origin in G.nodes:
            G.nodes[origin]["node_type"] = "origin"
        elif origin_type == "txid":
            # Mark all senders of the first TX as origin
            if transactions:
                first_tx = transactions[0]
                for s in first_tx["senders"]:
                    if s["address"] in G.nodes:
                        G.nodes[s["address"]]["node_type"] = "origin"

        # ── Classify leaf nodes as 'receiver' ──
        # A receiver node has no outgoing edges in our trace graph
        for node in G.nodes:
            if G.out_degree(node) == 0 and G.in_degree(node) > 0:
                G.nodes[node]["node_type"] = "receiver"

        # ── Serialize for JSON ──
        nodes = []
        for node_id, attrs in G.nodes(data=True):
            nodes.append({
                "id":             node_id,
                "node_type":      attrs.get("node_type", "intermediate"),
                "total_received": round(total_received.get(node_id, 0), 8),
                "total_sent":     round(total_sent.get(node_id, 0), 8),
                "in_degree":      G.in_degree(node_id),
                "out_degree":     G.out_degree(node_id),
            })

        edges = []
        for u, v, attrs in G.edges(data=True):
            edges.append({
                "source":    u,
                "target":    v,
                "txid":      attrs.get("txid", ""),
                "value":     round(attrs.get("value", 0), 8),
                "tx_count":  attrs.get("tx_count", 1),
            })

        return {"nodes": nodes, "edges": edges}

    # ─────────────────────────────────────────────
    # End-receiver detection heuristics
    # ─────────────────────────────────────────────

    def find_end_receivers(self, trace_result: dict) -> list:
        """
        Identify probable end receivers using these heuristics:

        H1 – No outgoing transactions observed in our trace (leaf node)
        H2 – Receives significantly more than it sends (accumulator)
        H3 – Appears at maximum depth of the trace chain

        Returns a list of dicts sorted by confidence score descending.
        """
        transactions = trace_result.get("transactions", [])
        if not transactions:
            return []

        outgoing: dict = defaultdict(float)
        incoming: dict = defaultdict(float)
        address_depth: dict = {}  # address → earliest depth it appears

        # Track depth using transaction order as proxy
        for depth_idx, tx in enumerate(transactions):
            for s in tx["senders"]:
                a = s["address"]
                outgoing[a] += s["value"]
                if a not in address_depth:
                    address_depth[a] = depth_idx
            for r in tx["receivers"]:
                a = r["address"]
                incoming[a] += r["value"]
                if a not in address_depth:
                    address_depth[a] = depth_idx

        all_addresses = set(incoming.keys()) | set(outgoing.keys())
        max_depth_idx = len(transactions) - 1

        candidates = []
        for addr in all_addresses:
            inc = incoming.get(addr, 0.0)
            out = outgoing.get(addr, 0.0)
            depth_idx = address_depth.get(addr, 0)

            # Score calculation (0–100)
            score = 0

            # H1: no outgoing activity → +40 pts
            if out == 0:
                score += 40

            # H2: net accumulator (receives more than it sends) → up to +35 pts
            if inc > 0:
                accumulation_ratio = max(0, (inc - out) / inc)
                score += int(accumulation_ratio * 35)

            # H3: appears deeper in the chain → up to +25 pts
            if max_depth_idx > 0:
                depth_score = (depth_idx / max_depth_idx) * 25
                score += int(depth_score)

            if score > 20:  # Only include meaningful candidates
                candidates.append({
                    "address":        addr,
                    "confidence":     min(score, 100),
                    "total_received": round(inc, 8),
                    "total_sent":     round(out, 8),
                    "net":            round(inc - out, 8),
                    "reason":         self._explain_receiver(out, inc, depth_idx, max_depth_idx),
                })

        # Sort by confidence descending, return top 10
        candidates.sort(key=lambda x: x["confidence"], reverse=True)
        return candidates[:10]

    def _explain_receiver(
        self, out: float, inc: float, depth_idx: int, max_depth: int
    ) -> str:
        """Human-readable explanation of why an address is flagged as end receiver."""
        reasons = []
        if out == 0:
            reasons.append("No outgoing transactions observed")
        if inc > out * 1.5 and inc > 0:
            reasons.append("Accumulates more than it sends forward")
        if max_depth > 0 and depth_idx >= max_depth * 0.7:
            reasons.append("Appears near end of traced chain")
        return "; ".join(reasons) if reasons else "Multiple weak signals"

    # ─────────────────────────────────────────────
    # Suspicious pattern detection
    # ─────────────────────────────────────────────

    def detect_suspicious_patterns(self, trace_result: dict) -> list:
        """
        Forensic pattern detection. Returns a list of flagged patterns, each:
        {
          "pattern":     short name,
          "description": human readable explanation,
          "severity":    "HIGH" | "MEDIUM" | "LOW",
          "evidence":    supporting data
        }

        Patterns checked:
          P1 – Many-to-many transactions (possible mixer / coinjoin)
          P2 – Equal-value output splitting (peel chain / splitting mixer)
          P3 – Rapid chaining (funds move through many wallets quickly)
          P4 – High fan-out (single wallet sends to many wallets at once)
        """
        transactions = trace_result.get("transactions", [])
        asset_symbol = trace_result.get("asset_symbol", "BTC")
        patterns = []

        if not transactions:
            return patterns

        # ── P1: Many-to-many (mixer heuristic) ──
        mixer_txs = [
            tx for tx in transactions
            if len(tx["senders"]) >= 3 and len(tx["receivers"]) >= 3
        ]
        if mixer_txs:
            patterns.append({
                "pattern":     "Possible Mixer / CoinJoin",
                "description": (
                    "Transactions with 3+ inputs AND 3+ outputs detected. "
                    "Common indicator of a coin mixer or CoinJoin coordination "
                    "used to obscure the origin of funds."
                ),
                "severity": "HIGH",
                "evidence": [t["txid"][:16] + "…" for t in mixer_txs[:3]],
            })

        # ── P2: Equal-value splitting ──
        for tx in transactions:
            values = [r["value"] for r in tx["receivers"]]
            if len(values) >= 3:
                unique = set(round(v, 5) for v in values)
                if len(unique) == 1:
                    patterns.append({
                        "pattern":     "Equal-Value Output Splitting",
                        "description": (
                            f"Transaction {tx['txid'][:16]}… splits funds into "
                            f"{len(values)} outputs of exactly equal value "
                            f"({values[0]} {asset_symbol} each). This is a hallmark of "
                            "automated laundering or fee-based mixing services."
                        ),
                        "severity": "HIGH",
                        "evidence": [tx["txid"][:16] + "…"],
                    })
                    break  # Report once

        # ── P3: Rapid fund chaining ──
        # More than 5 transactions in a short sequence suggests automated movement
        if len(transactions) >= 5:
            # Check if a single address appears as both sender and receiver
            # across consecutive transactions (peel chain)
            addresses_as_receiver = defaultdict(list)
            for i, tx in enumerate(transactions):
                for r in tx["receivers"]:
                    addresses_as_receiver[r["address"]].append(i)

            peel_addresses = [
                addr for addr, positions in addresses_as_receiver.items()
                if len(positions) >= 2 and
                   (max(positions) - min(positions)) <= 3
            ]

            if peel_addresses:
                patterns.append({
                    "pattern":     "Peel Chain / Rapid Chaining",
                    "description": (
                        "Funds appear to pass through several wallets in quick "
                        "succession. This 'peel chain' technique is used to "
                        "create distance between source and destination."
                    ),
                    "severity": "MEDIUM",
                    "evidence": [a[:20] + "…" for a in peel_addresses[:3]],
                })

        # ── P4: High fan-out ──
        for tx in transactions:
            if len(tx["receivers"]) >= 6:
                patterns.append({
                    "pattern":     "High Fan-Out Transaction",
                    "description": (
                        f"A single transaction sends funds to {len(tx['receivers'])} "
                        "different addresses. Could indicate automated distribution "
                        "or a mixing output stage."
                    ),
                    "severity": "MEDIUM",
                    "evidence": [tx["txid"][:16] + "…"],
                })
                break  # Report once

        return patterns
