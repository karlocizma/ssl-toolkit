#!/usr/bin/env python3
"""
Main entry point for the SSL Certificate Toolkit backend.
This module provides the Flask WSGI application for production servers (Gunicorn).
"""

from app import create_app
import os

# Create the Flask application instance
# This is used by Gunicorn with: gunicorn main:app
app = create_app()

if __name__ == "__main__":
    # Development server (for local testing only)
    # In production, use Gunicorn instead
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)