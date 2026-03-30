"""
nvidia/gliner-PII sidecar server for CloakPipe.

Runs as a lightweight HTTP service that CloakPipe's Rust detector calls
for NER-based PII detection (person names, addresses, organizations, etc.).

Start:  python tools/gliner-pii-server.py [--port 9111] [--threshold 0.4]
Health: curl http://localhost:9111/health
Detect: curl -X POST http://localhost:9111/detect -H 'Content-Type: application/json' \
             -d '{"text": "John Smith lives at 42 Oak St"}'

Requires: pip install gliner
"""

import argparse
import json
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# Entity labels to request — covers the categories CloakPipe's regex layers miss
DEFAULT_LABELS = [
    "first_name", "last_name",
    "company_name",
    "street_address", "city", "state", "country", "postcode",
    "date", "date_of_birth",
]


class GlinerHandler(BaseHTTPRequestHandler):
    """HTTP handler for GLiNER PII detection."""

    def do_GET(self):
        if self.path == "/health":
            self._json_response({"status": "ok", "model": "nvidia/gliner-pii"})
        else:
            self._json_response({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/detect":
            self._json_response({"error": "not found"}, 404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._json_response({"error": "invalid json"}, 400)
            return

        text = req.get("text", "")
        labels = req.get("labels", self.server.labels)
        threshold = req.get("threshold", self.server.threshold)

        if not text:
            self._json_response({"entities": []})
            return

        t0 = time.time()
        raw_entities = self.server.model.predict_entities(text, labels, threshold=threshold)
        elapsed_ms = (time.time() - t0) * 1000

        # Merge adjacent first_name + last_name into full names
        entities = merge_name_spans(raw_entities)

        result = {
            "entities": [
                {
                    "text": e["text"],
                    "label": e["label"],
                    "start": e["start"],
                    "end": e["end"],
                    "score": round(e["score"], 4),
                }
                for e in entities
            ],
            "elapsed_ms": round(elapsed_ms, 1),
        }
        self._json_response(result)

    def _json_response(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress default access logs; only log errors
        pass


def merge_name_spans(entities: list[dict]) -> list[dict]:
    """Merge adjacent first_name + last_name spans into a single 'person' entity."""
    if not entities:
        return []

    # Sort by start position
    sorted_ents = sorted(entities, key=lambda e: e["start"])
    merged = []
    i = 0

    while i < len(sorted_ents):
        curr = sorted_ents[i]

        # Check if current is first_name and next is last_name (or vice versa)
        if i + 1 < len(sorted_ents):
            nxt = sorted_ents[i + 1]
            name_labels = {"first_name", "last_name"}
            gap = nxt["start"] - curr["end"]

            if (curr["label"] in name_labels and nxt["label"] in name_labels
                    and curr["label"] != nxt["label"] and 0 <= gap <= 1):
                # Merge into single person entity
                merged.append({
                    "text": curr["text"] + (" " if gap == 1 else "") + nxt["text"],
                    "label": "person",
                    "start": curr["start"],
                    "end": nxt["end"],
                    "score": min(curr["score"], nxt["score"]),
                })
                i += 2
                continue

        # Non-name or standalone — keep the label but normalize single names
        if curr["label"] in ("first_name", "last_name"):
            curr = {**curr, "label": "person"}
        merged.append(curr)
        i += 1

    return merged


def main():
    parser = argparse.ArgumentParser(description="nvidia/gliner-PII sidecar for CloakPipe")
    parser.add_argument("--port", type=int, default=9111, help="Port (default: 9111)")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--threshold", type=float, default=0.4, help="Confidence threshold (default: 0.4)")
    args = parser.parse_args()

    print(f"Loading nvidia/gliner-PII model...")
    t0 = time.time()
    from gliner import GLiNER
    model = GLiNER.from_pretrained("nvidia/gliner-pii")
    print(f"Model loaded in {time.time() - t0:.1f}s")

    server = HTTPServer((args.host, args.port), GlinerHandler)
    server.model = model
    server.labels = DEFAULT_LABELS
    server.threshold = args.threshold

    print(f"GLiNER PII sidecar listening on http://{args.host}:{args.port}")
    print(f"  Labels: {', '.join(DEFAULT_LABELS)}")
    print(f"  Threshold: {args.threshold}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
