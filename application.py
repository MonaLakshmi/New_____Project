import os
import json
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import tenseal as ts
import base64

def setup_context():
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=8192,  
        coeff_mod_bit_sizes=[60, 40, 40, 60], 
        plain_modulus=1032193  
    )
    context.generate_galois_keys()
    context.generate_relin_keys()
    return context

application = Flask(__name__)
socketio = SocketIO(application)

CHAT_FILE = 'chat_messages.txt'
AUTH_FILE = 'authorize.txt'
CONTEXT_FILE='context.txt'
try:
    with open(CHAT_FILE, 'r') as file:
        messages = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
    messages = []
try:
    if os.path.exists(AUTH_FILE) and os.path.getsize(AUTH_FILE) > 0:
        with open(AUTH_FILE, 'r') as file:
            users = json.load(file)
    else:
        users = {}  
except (FileNotFoundError, json.JSONDecodeError):
    users = {}
try:
    if os.path.exists(CONTEXT_FILE) and os.path.getsize(CONTEXT_FILE) > 0:
        with open(CONTEXT_FILE, 'r') as file:
            contexts = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
    contexts = {}
# Store active user sessions
active_users = {}

contexts={}
@application.route('/')
def index():
    return render_template('index.html')

@socketio.on('register')
def register_user(data):
    username = data.get('username')
    password = data.get('password')

    if username in users:
        emit('register_response', {'status': 'fail', 'message': 'Username already exists!'})
    else:
        users[username] = password
        with open(AUTH_FILE, 'w') as file:
            json.dump(users, file)
        emit('register_response', {'status': 'success', 'message': 'Registration successful! Please log in.'})

@socketio.on('login')
def login_user(data):
    username = data.get('username')
    password = data.get('password')

    if username in users and users[username] == password:
        active_users[username] = request.sid  
        emit('login_response', {'status': 'success', 'message': 'Login successful!', 'chat_history': messages})
    else:
        emit('login_response', {'status': 'fail', 'message': 'Invalid username or password'})

@socketio.on('send_message')
def handle_message(data):
    sender = data.get('username')
    recipient = data.get('recipient')
    message = data.get('message')
    
    if recipient not in users:
        emit('receive_message', {'username': 'System', 'message': f'User {recipient} does not exist.'}, room=active_users.get(sender))
        return
    key=f"{sender}_{recipient}"
    if key not in contexts:
        context = setup_context()
        context_serialized = base64.b64encode(context.serialize(save_secret_key=True)).decode('utf-8')
        contexts[key] = context_serialized  
       
    else:
        context=ts.context_from(base64.b64decode(contexts[key].encode('utf-8')))
    
    encrypted = ts.bfv_vector(context, [ord(c) for c in message])
    encrypted_serialized = base64.b64encode(encrypted.serialize()).decode('utf-8')
    encrypted_vector = ts.bfv_vector_from(context, base64.b64decode(encrypted_serialized.encode('utf-8')))
    #Decrypted part
    
    decrypted_chars = encrypted_vector.decrypt() 
    decrypted_text = "".join(chr(int(c)) for c in decrypted_chars)
    chat_entry = {'sender': sender, 'recipient': recipient, 'message':decrypted_text}
    messages.append(chat_entry)
    with open(CONTEXT_FILE,'w') as file:
        json.dump(contexts,file)
    with open(CHAT_FILE, 'w') as file:
        json.dump(messages, file)

    if recipient in active_users:
        emit('receive_message', chat_entry, room=active_users[recipient])
    

if __name__ == '__main__':
    socketio.run(application, host='0.0.0.0', debug=True)

