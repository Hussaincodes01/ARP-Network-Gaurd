"""Vercel entrypoint: the FastAPI app (the dashboard itself is served from public/)."""
from arpguard.api.main import app

__all__ = ["app"]
