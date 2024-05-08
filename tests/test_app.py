import pytest
from discovery_server import app, db, User, Message
from datetime import datetime

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    client = app.test_client()

    with app.app_context():
        db.create_all()

    yield client

    with app.app_context():
        db.drop_all()

def register_user(client, username, password, port):
    return client.post('/register', json={
        'username': username,
        'password': password,
        'port': port
    })

def login_user(client, username, password):
    return client.post('/login', json={
        'username': username,
        'password': password
    })

def test_register(client):
    """Test user registration."""
    response = register_user(client, 'testuser', 'testpass', 12345)
    assert response.status_code == 200
    assert b"Registration successful" in response.data

def test_login(client):
    """Test user login."""
    # First register a user
    register_user(client, 'testuser', 'testpass', 12345)

    # Now, try to login
    response = login_user(client, 'testuser', 'testpass')
    assert response.status_code == 200
    assert b"Login successful" in response.data

def test_send_message(client):
    """Test sending a message."""
    # Register users
    register_user(client, 'sender', 'pass123', 12345)
    register_user(client, 'receiver', 'pass456', 54321)

    # Login sender
    login_user(client, 'sender', 'pass123')

    # Send message from sender to receiver
    response = client.post('/messages', json={
        'toUser': 2,  # Assuming ID 2 is assigned to 'receiver'
        'message': 'Hello!'
    })
    assert response.status_code == 200
    assert b"Message sent successfully" in response.data

def test_get_messages(client):
    """Test retrieving messages."""
    # Register and login users
    register_user(client, 'sender', 'pass123', 12345)
    register_user(client, 'receiver', 'pass456', 54321)
    login_user(client, 'sender', 'pass123')

    # Send message
    client.post('/messages', json={
        'toUser': 2,
        'message': 'Hello!'
    })

    # Retrieve messages
    response = client.get('/messages')
    assert response.status_code == 200
    messages = response.get_json()
    assert len(messages) == 1
    assert messages[0]['content'] == 'Hello!'

def test_lookup_user(client):
    """Test user lookup."""
    register_user(client, 'testuser', 'testpass', 12345)
    response = client.get('/lookup', query_string={'username': 'testuser'})
    assert response.status_code == 200
    user_info = response.get_json()
    assert user_info['port'] == 12345

def test_error_handling(client):
    """Test error handling for non-existent user login."""
    response = login_user(client, 'nonuser', 'nopass')
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data
