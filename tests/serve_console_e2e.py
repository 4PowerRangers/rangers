import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import uvicorn


class LocalFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond({"ok": True, "data": [], "message": "Ranger E2E fixture"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        action = {"action": "http_request", "method": "GET", "path": "/rest/products/search?q=e2e"}
        self.respond({
            "model": body.get("model"),
            "choices": [{"message": {"content": json.dumps(action)}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        })

    def respond(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    os.environ["RANGER_MODEL_ENDPOINT"] = "http://127.0.0.1:18090"
    os.environ["RANGER_DB_OBSERVER_TOKEN"] = "ranger-local-e2e-observer"
    for port in (18090, 18001):
        server = ThreadingHTTPServer(("127.0.0.1", port), LocalFixture)
        Thread(target=server.serve_forever, daemon=True).start()
    uvicorn.run("console.backend.main:app", host="127.0.0.1", port=8001)
