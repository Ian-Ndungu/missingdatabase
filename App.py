from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///missing_persons.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = '29d4ab7de0c65efa94a08cdf6e08a9b4b335e513e76866cc38805b596bfc1a21'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Enable CORS for all routes
CORS(app, resources={r"/*": {"origins": "*"}})

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = app.make_response('')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        return response

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class MissingPerson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    photo_url = db.Column(db.String(200), nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    last_known_location = db.Column(db.String(200), nullable=False)
    contact_info = db.Column(db.String(200), nullable=False)

@app.route('/')
@jwt_required(optional=True)
def index():
    persons = MissingPerson.query.all()
    return render_template('index.html', persons=persons)

@app.route('/add', methods=['GET', 'POST'])
@jwt_required()
def add_person():
    if request.method == 'POST':
        current_user = get_jwt_identity()
        name = request.form['name']
        age = request.form['age']
        photo_url = request.form['photo_url']
        occupation = request.form['occupation']
        last_known_location = request.form['last_known_location']
        contact_info = request.form['contact_info']
        
        new_person = MissingPerson(
            name=name,
            age=age,
            photo_url=photo_url,
            occupation=occupation,
            last_known_location=last_known_location,
            contact_info=contact_info
        )
        
        db.session.add(new_person)
        db.session.commit()
        
        return redirect(url_for('index'))
    
    return render_template('add_person.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'User already exists'}), 400
    
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'msg': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity={'username': username})
        return jsonify(access_token=access_token)
    
    return jsonify({'msg': 'Invalid credentials'}), 401

if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=80, debug=True)
