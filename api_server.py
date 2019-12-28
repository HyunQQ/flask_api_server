import datetime
import uuid
import jwt

from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
""" 
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand 
"""

app = Flask(__name__)

app.config["SECRET_KEY"] = "5791628bb0b13ce0c676dfde280ba245"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///bestill2.db"

db = SQLAlchemy(app)

""" migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand) """

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    notes = db.relationship('Note', backref='author')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.public_id}')"

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    date_last_updated = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    scripture = db.Column(db.String(100))
    is_public = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.String(50), db.ForeignKey('user.public_id'), nullable=False)

    def __repr__(self):
        return f"Note('{self.title}', '{self.author}', '{self.is_public}')"

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"Notice('{self.title}', '{self.content}')"

class DailyQT(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Datetime, nullable=False)
    book = db.Column(db.Integer, nullable=False)
    chapter_from = db.Column(db.Integer, nullable=False)
    chapter_to = db.Column(db.Integer, nullable=False)
    verse_from = db.Column(db.Integer, nullable=False)
    verse_to = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"DailyQT('{self.id}', '{self.date}', {self.book}, {self.chapter_from}, {self.chapter_to}, {self.verse_from}, {self.verse_to})"


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
    
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/')
def index():
    return "안녕하세요. 묵상나눔 API Server 입니다!"

@app.route('/login', methods=['POST'])
def login():
    
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verity', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verity', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verity', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/login-test')
@login_required
def login_test(current_user):

    print(current_user)

    return current_user.email

# Create
# Create - User
@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_password)

    # username 중복성 체크

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created!'})

# Create - Note
@app.route('/note', methods=['POST'])
def create_note():

    data = request.get_json()

    new_note = Note(title=data['title'], content=data['content'], scripture=data['scripture'], is_public=data['is_public'], user_id=data['user_id'])

    db.session.add(new_note)
    db.session.commit()

    return jsonify({'message': 'Note created!'})

# Create - Notice
@app.route('/notice', methods=['POST'])
def create_notice():

    data = request.get_json()

    new_notice = Notice(title=data['title'], content=data['content'])

    db.session.add(new_notice)
    db.session.commit()

    return jsonify({'message': 'Notice created!'})


# Read
# Read - User
@app.route('/user', methods=['GET'])
def get_all_users():
    
    users = User.query.all()

    users_list = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['email'] = user.email
        users_list.append(user_data)

    return jsonify(users_list)

@app.route('/user/<string:user_id>', methods=['GET'])
def get_user(user_id):
    
    user = User.query.filter_by(public_id=user_id).first()

    if not user:
        return jsonify({'message' : 'No user found'})

    user_data = {}
    user_data['id'] = user.id
    user_data['user_id'] = user.public_id
    user_data['username'] = user.username
    user_data['email'] = user.email

    return jsonify(user_data)

# Read - Note
@app.route('/note', methods=['GET'])
def get_all_notes():
    
    notes = Note.query.all()

    notes_list = []

    for note in notes:
        note_data = {}
        note_data['id'] = note.id
        note_data['title'] = note.title
        note_data['content'] = note.content
        note_data['date_posted'] = note.date_posted.strftime("%Y-%m-%d")
        note_data['scripture'] = note.scripture
        note_data['username'] = note.author.username
        note_data['is_public'] = note.is_public
        notes_list.append(note_data)

    return jsonify(notes_list)

@app.route('/note/<int:note_id>', methods=['GET'])
def get_note_by_id(note_id):

    note = Note.query.filter_by(id=note_id).first()

    if not note:
        return jsonify({'message' : 'No note found'})

    note_data = {}
    note_data['id'] = note.id
    note_data['title'] = note.title
    note_data['content'] = note.content
    note_data['date_posted'] = note.date_posted.strftime("%Y-%m-%d")
    note_data['scripture'] = note.scripture
    note_data['username'] = note.author.username
    note_data['is_public'] = note.is_public

    return jsonify(note_data)

@app.route('/note/<string:user_public_id>', methods=['GET'])
def get_notes_by_username(user_id):

    note = Note.query.filter_by(user_id=user_id).all()

    notes_list = []

    if not note:
        return jsonify({'message' : 'No note found'})

    for note in notes:
        note_data = {}
        note_data['id'] = note.id
        note_data['title'] = note.title
        note_data['content'] = note.content
        note_data['date_posted'] = note.date_posted.strftime("%Y-%m-%d")
        note_data['scripture'] = note.scripture
        note_data['username'] = note.author.username
        note_data['is_public'] = note.is_public
        notes_list.append(note_data)

    return jsonify(notes_list)

# Read - Notice
@app.route('/notice', methods=['GET'])
def get_all_notice():

    notices = Notice.query.all()

    if not notices:
        return jsonify({'message' : 'No notice found'})

    notice_list = []
    top_notice_num = 2
    
    for notice in notices:
        notice_data = {}
        notice_data['id'] = notice.id
        notice_data['title'] = notice.title
        notice_data['content'] = notice.content
        notice_data['date_posted'] = notice.date_posted.strftime("%Y-%m-%d")
        notice_list.append(notice_data)

    return jsonify(notice_list)

@app.route('/notice/<int:notice_id>', methods=['GET'])
def get_notice(notice_id):

    notice = Notice.query.filter_by(id=notice_id).first()

    notice_data = {}
    notice_data['title'] = notice.title
    notice_data['content'] = notice.content
    notice_data['date_posted'] = notice.date_posted.strftime("%Y-%m-%d")

    return jsonify(notice_data)


# Update
# Update - User
@app.route('/user/<string:user_id>', methods=['PUT'])
def update_user(user_id):

    data = request.get_json()

    user = User.query.filter_by(public_id=user_id).first()

    if not user:
        return jsonify({'message' : 'No user found'})

    user.username = data['username']
    user.email = data['email']
    user.password = data['password']

    db.session.commit()

    return jsonify({'message': 'User updated!'})

# Update - Note
@app.route('/note/<int:note_id>', methods=['PUT'])
def update_note(note_id):

    data = request.get_json()

    note = Note.query.filter_by(id=note_id).first()

    note.title = data['title']
    note.content = data['content']
    note.date_last_updated = datetime.utcnow()

    db.session.commit()

    return jsonify({'message': 'Note updated!'})

# Update - Notice
@app.route('/notice/<int:notice_id>', methods=['PUT'])
def update_notice(notice_id):

    data = request.get_json()

    notice = Notice.query.filter_by(id=notice_id).first()

    notice.title = data['title']
    notice.content = data['content']

    db.session.commit()

    return jsonify({'message': 'Notice updated!'})


# Delete
# Delete - User
@app.route('/user/<string:user_id>', methods=['DELETE'])
def delete_user(user_id):

    user = User.query.filter_by(public_id=user_id).first()

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted!'})

# Delete - Note
@app.route('/note/<int:note_id>', methods=['DELETE'])
def delete_note(note_id):

    note = Note.query.filter_by(id=note_id).first()

    db.session.delete(note)
    db.session.commit()

    return jsonify({'message': 'Note deleted!'})

# Delete - Notice
@app.route('/notice/<int:notice_id>', methods=['DELETE'])
def delete_notice(notice_id):

    notice = Notice.query.filter_by(id=notice_id)

    db.session.delete(notice)
    db.session.commit()

    return jsonify({'message': 'Notice deleted!'})


if __name__ == '__main__':
  app.run(debug=True)
  #manager.run()