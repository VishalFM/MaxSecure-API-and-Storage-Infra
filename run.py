from app import create_app
from app.routes import malware_routes, redis_routes


app = create_app()

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

app.register_blueprint(malware_routes.signature_blueprint1, url_prefix='/app/pages')

if __name__ == '__main__':
    app.run(debug=True)
