from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError  # Import for handling unique constraint errors

app = Flask(__name__)
# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///p2p_messaging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    ip_address = db.Column(db.String(120), nullable=False)
    port = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@app.route('/')
def home():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    port = data.get('port')
    ip_address = request.remote_addr
    # Check if the user already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409
    user = User(username=username, ip_address=ip_address, port=port)
    db.session.add(user)
    try:
        db.session.commit()
        return jsonify({"message": f"{username} registered successfully!"})
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "This username is already taken."}), 400

@app.route('/lookup', methods=['GET'])
def lookup():
    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"ip_address": user.ip_address, "port": user.port})
    else:
        return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created.
    app.run(debug=True)
