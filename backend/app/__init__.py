from flask import Flask, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

def get_api_key_or_ip():
    """Get API key from header or fall back to IP address for rate limiting"""
    api_key = request.headers.get('X-API-Key')
    if api_key:
        return f"api_key:{api_key}"
    return get_remote_address()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    app.config['UPLOAD_FOLDER'] = '/tmp/ssl-toolkit'
    
    # Enable CORS
    CORS(app)
    
    # Enhanced rate limiting with API key support
    limiter = Limiter(
        key_func=get_api_key_or_ip,
        default_limits=["200 per hour", "50 per minute"],
        storage_uri="memory://"
    )
    limiter.init_app(app)
    
    # Store limiter in app context for use in routes
    app.limiter = limiter
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Register blueprints
    from app.routes.ssl_routes import ssl_bp
    app.register_blueprint(ssl_bp, url_prefix='/api')
    
    return app
