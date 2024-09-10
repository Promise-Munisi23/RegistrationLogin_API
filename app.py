from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from config import Config
from models import db, bcrypt, User

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
jwt = JWTManager(app)

# Initialize the database within an application context
with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'email': user.email})
        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Welcome {current_user["username"]}'})

if __name__ == '__main__':
    app.run(debug=True)



# from flask import Flask, request, jsonify
# from flask_sqlalchemy import SQLAlchemy
# from flask_bcrypt import Bcrypt
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from config import Config
# from models import db, bcrypt, User

# app = Flask(__name__)
# app.config.from_object(Config)

# db.init_app(app)
# bcrypt.init_app(app)
# jwt = JWTManager(app)

# @app.before_first_request
# def create_tables():
#     db.create_all()


# @app.route('/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
#     user = User(username=data['username'], email=data['email'], password=hashed_password)
#     db.session.add(user)
#     db.session.commit()
#     return jsonify({'message': 'User created successfully'}), 201

# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     user = User.query.filter_by(email=data['email']).first()
#     if user and bcrypt.check_password_hash(user.password, data['password']):
#         access_token = create_access_token(identity={'username': user.username, 'email': user.email})
#         return jsonify({'access_token': access_token}), 200
#     return jsonify({'message': 'Invalid credentials'}), 401

# @app.route('/protected', methods=['GET'])
# @jwt_required()
# def protected():
#     current_user = get_jwt_identity()
#     return jsonify({'message': f'Welcome {current_user["username"]}'})

# if __name__ == '__main__':
#     app.run(debug=True)

