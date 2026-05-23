"""Crypto Transaction Trail Analyzer Flask application."""

import os

from flask import Flask, render_template, request, jsonify
from tracer import BitcoinTracer, EthereumTracer
from graph_builder import GraphBuilder
import json

app = Flask(__name__)

# ─────────────────────────────────────────────
# Route: Home page
# ─────────────────────────────────────────────
@app.route("/")
def index():
    """Render the main UI page."""
    return render_template("index.html")


# ─────────────────────────────────────────────
# Route: Analyze a crypto address or TX hash
# ─────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    POST endpoint that accepts a Bitcoin or Ethereum address/transaction hash,
    traces funds up to a configurable depth, and returns graph data + analysis.
    """
    data = request.get_json()
    query = data.get("query", "").strip()
    chain = (data.get("chain", "bitcoin") or "bitcoin").strip().lower()
    depth = int(data.get("depth", 3))  # default hop depth = 3

    if not query:
        return jsonify({"error": "No input provided."}), 400

    # Clamp depth between 1 and 5 to avoid API rate limits
    depth = max(1, min(depth, 5))

    if chain not in {"bitcoin", "ethereum"}:
        return jsonify({"error": "Unsupported chain. Use 'bitcoin' or 'ethereum'."}), 400

    try:
        tracer = BitcoinTracer() if chain == "bitcoin" else EthereumTracer()
        builder = GraphBuilder()

        # Step 1: Determine if input is a wallet address or transaction hash
        input_type = tracer.detect_input_type(query)

        # Step 2: Fetch and trace transactions
        if input_type == "address":
            trace_result = tracer.trace_from_address(query, max_depth=depth)
        elif input_type == "txid":
            trace_result = tracer.trace_from_transaction(query, max_depth=depth)
        else:
            if chain == "bitcoin":
                msg = "Invalid Bitcoin address or transaction hash."
            else:
                msg = "Invalid Ethereum address or transaction hash."
            return jsonify({"error": msg}), 400

        if "error" in trace_result:
            return jsonify(trace_result), 400

        # Step 3: Build graph from trace data
        graph_data = builder.build_graph(trace_result)

        # Step 4: Detect suspicious patterns
        patterns = builder.detect_suspicious_patterns(trace_result)

        # Step 5: Identify probable end receivers
        end_receivers = builder.find_end_receivers(trace_result)

        return jsonify({
            "input_type": input_type,
            "chain": chain,
            "asset_symbol": trace_result.get("asset_symbol", "BTC"),
            "query": query,
            "graph": graph_data,
            "patterns": patterns,
            "end_receivers": end_receivers,
            "total_nodes": len(graph_data["nodes"]),
            "total_edges": len(graph_data["edges"]),
            "hops_traced": trace_result.get("max_depth_reached", depth),
        })

    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


# ─────────────────────────────────────────────
# Route: Fetch raw transaction details
# ─────────────────────────────────────────────
@app.route("/tx/<txid>")
def tx_detail(txid):
    """Return raw details for a single transaction."""
    try:
        chain = (request.args.get("chain", "bitcoin") or "bitcoin").strip().lower()
        tracer = BitcoinTracer() if chain == "bitcoin" else EthereumTracer()
        tx = tracer.fetch_transaction(txid)
        if tx is None:
            return jsonify({"error": "Transaction not found."}), 404
        return jsonify(tx)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 50)
    print("  Crypto Transaction Trail Analyzer (BTC + ETH)")
    print("  Running at http://127.0.0.1:5000")
    print("=" * 50)
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
