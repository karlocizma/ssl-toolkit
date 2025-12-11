#!/usr/bin/env python3
"""
Main entry point for the SSL Certificate Toolkit backend.
This module provides compatibility for both WSGI and ASGI servers.
"""

from app import create_app
import os

# Create the Flask application instance
app = create_app()

# For ASGI compatibility (uvicorn, etc.)
# This allows the app to be imported as main:app
app_asgi = app

# For WSGI compatibility (gunicorn, etc.)
if __name__ == "__main__":
    # Development server
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)