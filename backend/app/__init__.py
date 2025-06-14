from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    app.config['UPLOAD_FOLDER'] = '/tmp/ssl-toolkit'
    
    # Enable CORS
    CORS(app)
    
    # Rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["100 per hour"]
    )
    limiter.init_app(app)
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Register blueprints
    from app.routes.ssl_routes import ssl_bp
    app.register_blueprint(ssl_bp, url_prefix='/api')
    
    return app

