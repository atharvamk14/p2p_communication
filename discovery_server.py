from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import render_template
from datetime import datetime
import rq
from redis import Redis
from rq.job import Job


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///p2p_messaging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "abcdef"
db = SQLAlchemy(app)
redis_conn = Redis()
queue = rq.Queue(connection=redis_conn)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    ip_address = db.Column(db.String(120), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
@app.route('/')
def home():
    return render_template('register.html')   

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    ip_address = request.remote_addr
    port = data['port']
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 409
    user = User(username=username, ip_address=ip_address, port=port, password=password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Registration successful"})

@app.route('/lookup', methods=['GET'])
def lookup():
    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'ip_address': user.ip_address, 'port': user.port})
    return jsonify({'error': 'User not found'}), 404

@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def process_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        session['user_id'] = user.id  # Store user info in session
        session['username'] = username
        return jsonify({"message": "Login successful!", "redirect": "/chats"})
    else:
        return jsonify({"error": "Invalid username or password"}), 401
    
@app.route('/chats')
def chats():
    if 'user_id' not in session:
        return redirect('/login')  # Redirect to login if not authenticated
    return render_template('messaging.html')  # Load the chat interface

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'username': user.username} for user in users])

@app.route('/messages', methods=['POST', 'GET'])
def handle_messages():
    if request.method == 'POST':
        data = request.get_json()
        new_message = Message(sender_id=session['user_id'], receiver_id=data['toUser'], content=data['message'])
        db.session.add(new_message)
        db.session.commit()
        return jsonify({'message': 'Message sent successfully'})
    elif request.method == 'GET':
        messages = Message.query.filter((Message.sender_id == session['user_id']) | (Message.receiver_id == session['user_id'])).all()
        return jsonify([{'sender': msg.sender_id, 'receiver': msg.receiver_id, 'content': msg.content, 'timestamp': msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for msg in messages])

@app.route('/queued_messages')
def view_queued_messages():
    jobs = queue.jobs  # Retrieves all jobs in the queue
    messages = [{'id': job.id, 'status': job.get_status()} for job in jobs]
    return jsonify(messages)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

