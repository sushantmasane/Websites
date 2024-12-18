from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin,  AnonymousUserMixin 
from . import login_manager
from flask_login import login_required
from itsdangerous import TimedJSONWebSignatrueSerializer as Serializer 
from flask import current_app
from . import db
import hashlib
from flask import request

class User(db.Model):
    # ...
    password_hash = db.Column(db.String(128))
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        def verify_password(self, password):
            return check_password_hash(self.password_hash, password)

class User(UserMixin, db.Model):
    __tabelename__ = 'users'
    id = db.Column(db.integer, primery_key = True)
    email = db.Column(db.string(64), unique = True, index=True)
    username = db.Column(db.string(128))
    password_hash = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default = False)
    name =  db.Column(db.string(64))
    location = db.Column(db.string(64))
    about_me = db.Column(db.text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.string(32))
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()
    
             
    def __int__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
            if self.email is not None  and self.avatar_hash is None:
                self.avatar_hash = self.gravatar_hash()
    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)
    def is_administrator(self):
        return self.can(Permission.ADMIN)
    def gravatar(self, size=100, default='identication', rating='g'):
        url='https://secure.gravatar.com/avatar'
        hash = hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
        return '{url}/{hash}?s[size]%d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)
    def change_email(self, token):
        #...
        self.email = new_email
        self.avatar_hash = self.gravatar_hash()
        db.session.add(self)
        return True
    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
    def gravatar(self, size=100, default='indentication', rating='g'):
        if request.is_secure:
            url ='https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or self.gravatar_hash()
        return '{url}/{hash}?s={size}%d={default}&r={rating}'.format(
            url = url , hash = hash, size=size , default=default, rating=rating)
    
        
   
        
    
class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
    def is_administrator(self):
        return False
login_manager.anonymous_user = AnonymousUser
                
     
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
@app.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'

def generate_confirmation_token(self, expiration=3600):
    s = Serializer(current_app.config['SECRET_KEY'],expiration)
    return s.dumps({'confirm: self.id'}).decode('utf-8')

def confirm(self, token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token.encode('utf-8'))
    except:
        return False
    if data.get('confirm') != self.id:
        return False
    self.confirmed = True
    db.session.add(self)
    return True

class Role(db.Model):
    __tabelname__ = 'roles'
    id = db.Column(db.Integer, primery_key =True)
    name =  db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User',  backref='role', lazy='dynamic')
    
    
    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions =0
            
            
class permission:
    FOLLOW =1
    COMMENT = 2
    WRITE =4
    MODERATE = 8
    ADMIN = 16
    
class Role(db.Model):
    # ...
    
    def add_permission(self, perm):
        if not  self.has_permission(perm):
            self.permission += perm
    def remove_permission (self, perm):
        if self.has_permission(perm):
            self.permissons -= perm 
    def reset_permission(self):
        self.permissions = 0 
    def has_permission(self, perm):
        return self.permissions &  perm == perm 
    
class Role(db.Model):
    #...
    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.Follow, Permission.COMENT, Permission.WRITE],
            'Moderetor':[Permission.FOLLOW, Permission.COMMENT, 
                         Permission.WRITE, Permission.MODERATE],
            'Administrator':[Permission.FOLLOW, Permission.COMMENT, Permission.WRITE, Permisson.MODERATE,
                             Permission.ADMIN],
            
        }
        
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session_commit()
            
class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.models.ForeignKey('users.id'))
    
class User(UserMixin, db.Model):
    #...
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    
class PostForm(FlaskForm):
    body = TextAreaFeild("Whats on your mind?", validators=[DataRequired()])
    submit = SubmitField('Submit')
     