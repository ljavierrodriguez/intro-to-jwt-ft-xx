import os
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt_identity, create_access_token, jwt_required
from models import db, User
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
# Flask Config
app.url_map.strict_slashes = False
app.config['DEBUG'] = True
app.config['ENV'] = 'development'

# Config Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASEURI')

# Config JWT 
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')

db.init_app(app)

# Config Migrations with SQLAlchemy
Migrate(app, db) # db init, db migrate, db upgrade, db downgrade 

# Config JWT
jwt = JWTManager(app)

@app.route('/')
def main():
    return jsonify({ "API": "API Rest with Postgresql"})

@app.route('/api/register', methods=['POST'])
def register():
    
    username = request.json.get('username')
    password = request.json.get('password')
    
    if not username: return jsonify({"msg": "username is required"}), 400
    if not password: return jsonify({"msg": "password is required"}), 400
    
    userFound = User.query.filter_by(username=username).first()
    if userFound: return jsonify({"msg": "username is already taken"}), 400
    
    user = User()
    user.username = username
    user.password = generate_password_hash(password)
    user.save()
    
    return jsonify({ "success": "User created successfully", "status": 201, "data": user.serialize()}), 201

@app.route('/api/login', methods=['POST'])
def login():
    
    username = request.json.get('username')
    password = request.json.get('password')
    
    if not username: return jsonify({"msg": "username is required"}), 400
    if not password: return jsonify({"msg": "password is required"}), 400
    
    userFound = User.query.filter_by(username=username).first()
    if not userFound: 
        return jsonify({"error": "username/password is incorrect"}), 401
    
    if not check_password_hash(userFound.password, password):
        return jsonify({"error": "username/password is incorrect"}), 401
        
    # Generar el JWT Token
    access_token = create_access_token(identity=userFound.id)
    
    data = {
        "access_token": access_token,
        "user": userFound.serialize()
    }
    
    return jsonify({ "success": "Login successfully", "status": 200, "data": data}), 200


@app.route('/api/profile', methods=['GET'])
@jwt_required() # Definiendo una ruta privada
def profile():
    id = get_jwt_identity()
    user = User.query.get(id)
    return jsonify({ "message": "Private Route", "user": user.username }), 200

if __name__ == '__main__':
    app.run()