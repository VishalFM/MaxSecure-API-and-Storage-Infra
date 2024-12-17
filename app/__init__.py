from flask import Flask
from app.routes import malicious_url_routes, malware_routes, redis_routes, connection_routes
from app.extensions import db

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)

    # malware
    app.register_blueprint(malware_routes.file_type_bp)
    app.register_blueprint(malware_routes.source_bp)
    app.register_blueprint(malware_routes.spyware_category_bp)
    app.register_blueprint(malware_routes.spyware_name_bp)
    app.register_blueprint(malware_routes.signature_blueprint)
    app.register_blueprint(malware_routes.white_file_blueprint)
    app.register_blueprint(malware_routes.hits_blueprint)

    # malicious url
    app.register_blueprint(malicious_url_routes.malicious_urls_bp)

    # testing connections
    app.register_blueprint(connection_routes.test)
    app.register_blueprint(connection_routes.pg_connection)

    # app.register_blueprint(malware_routes.signature_blueprint1, url_prefix='/app/pages')
    app.register_blueprint(redis_routes.redis_bp)

    return app
