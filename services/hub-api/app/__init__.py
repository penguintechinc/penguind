"""hub-api: CLI-only management hub for penguind agents (Quart service)."""

from app.factory import create_app

__all__ = ["create_app"]
