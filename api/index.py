import os
import sys

# Ensure project root is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from starlette.types import ASGIApp, Scope, Receive, Send
from app import app as fastapi_app

class VercelASGIAdapter:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            matched_path = headers.get(b"x-matched-path")
            if matched_path:
                decoded = matched_path.decode("utf-8").split("?")[0]
                scope["path"] = decoded
            elif scope.get("path") in ("/api/index.py", "/api", "/api/"):
                scope["path"] = "/"
            elif scope.get("path", "").startswith("/api/index.py/"):
                scope["path"] = scope["path"][len("/api/index.py"):]
        await self.app(scope, receive, send)

app = VercelASGIAdapter(fastapi_app)
