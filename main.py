from werkzeug.security import generate_password_hash, check_password_hash
import email_validator
from time import sleep, time, strftime
import secrets 
from flask import Flask, render_template, redirect, url_for, flash, request, session, g, send_file, abort, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, Email
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import threading
from flask_mail import Mail, Message
from smtplib import SMTP
from io import BytesIO
from werkzeug.utils import secure_filename
import string
from requests import get, delete,post
from json import loads
import uuid
import collections
from sqlite3 import connect
import traceback
from numpy import array
from os import getenv, fstat
import logging
from logging.handlers import RotatingFileHandler
from secrets import randbits, token_urlsafe
from math import ceil
import base64
from pickle import dumps
from pickle import loads as pe

app = Flask(__name__)
app.config['SECRET_KEY'] = 'VERY-IMPORTANT-KEY' # what does this key even do? I know its really important for the security
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'skyboxcloud0@gmail.com'
app.config['MAIL_PASSWORD'] = getenv('EMAIL')
app.config['MAIL_DEFAULT_SENDER'] = 'skyboxcloud0@gmail.com'
app.secret_key = "VERY-IMPORTANT-KEY"

mail = Mail(app)

conn = connect('final.db',check_same_thread=False)
c = conn.cursor()

lock = threading.Lock()
lockdiscord = threading.Lock()

imagefiletypes = ["rgb","gif","pbm","pgm","ppm","tiff","rast","xbm","jpeg","jpg","bmp","png","webp","exr"]
videofiletypes = ["mp4","avi","mpeg-4","wmv","divx","webm","flv"]
audiofiletypes = ["mp3","ogg","wav"]

def dbs(s,t):
  lock.acquire(True)
  c.execute(s[0],s[1])
  conn.commit()
  lock.release()
  if t:
    return c.fetchall()
  return c.fetchone()

def generate_verification_code():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120), index=True, unique=True)
    email_sent_at = db.Column(db.DateTime)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_code = db.Column(db.String(6))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_reset_token = db.Column(db.String(64))
    password_reset_token_expiry = db.Column(db.DateTime)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def validate_email(email):
    user = User.query.filter_by(email=email.lower()).first()
    if user:
        return 'Email address already in use.'
    else:
      return "Success"

def validate_name(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return 'username address already in use.'
    else:
      return "Success"

def send_verification_email(user):
    verification_code = generate_verification_code()
    message = Message('Verify your email', recipients=[user.email])
    message.body = f'Thank you for signing up. Your verification code is {verification_code}.'
    print(verification_code)
    mail.send(message)
    user.email_sent_at = datetime.utcnow()
    user.email_verified = False
    user.email_verification_code = verification_code
    db.session.commit()

def delete_unverified_accounts():
  with app.app_context():
    users = User.query.filter_by(email_verified=False).all()
    for user in users:
        try:
          if user.email_sent_at < datetime.utcnow() - timedelta(minutes=5):
              db.session.delete(user)
              db.session.commit()
        except:
          db.session.delete(user)

def run_every_five_seconds():
    while True:
        t = threading.Timer(5.0, delete_unverified_accounts)
        t.start()
        t.join()
threading.Thread(target=run_every_five_seconds).start()

def sizeof_fmt(num, suffix="B"):
    num = int(num)
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi","Ei","Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f} Yi{suffix}"

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])
    confirm  = PasswordField('Confirm Password')
    submit   = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(max=80)])
    submit   = SubmitField('Log In')

class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Reset')

class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
    submit = SubmitField('Next')

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True
    g.user = current_user

@app.route('/')
def index():
    if current_user.is_authenticated:
      return redirect(url_for('profile'))
    lock.acquire(True)
    c.execute('SELECT COUNT(*) FROM Attachments')
    uploads = str(c.fetchone()[0])
    
    c.execute('SELECT Size FROM Attachments')
    k = 0
    
    for i in c.fetchall():
      k+=i[0]
    l = sizeof_fmt(k)

    usercount = str(User.query.count())
    lock.release()
    return render_template('home.html', uploadcount = uploads, size = l, usercount = usercount)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
      flash('To signup, please sign out of your current account first.')
      return redirect(url_for('profile'))
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        username = form.username.data
        if 'anonymous' in username.lower():
          flash('Cannot use this username')
        elif not (validate_email(email) == "Success"):
          flash('Email already in use')
        elif not (validate_name(username) == "Success"):
          flash('Username already in use')
        else:
          user = User(username=form.username.data, email=form.email.data.lower())
          user.set_password(form.password.data)
          db.session.add(user)
          db.session.commit()
          send_verification_email(user)
          return redirect(url_for('verify', username=form.username.data))
    return render_template('signup.html', form=form)

@app.route('/verify/<username>', methods=['GET', 'POST'])
def verify(username):
    user = User.query.filter_by(username=username).first_or_404() 
    if user.email_verified:
        flash('Your account has already been verified. Please log in.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form['verification_code'] == user.email_verification_code:
            user.email_verified = True
            db.session.commit()
            flash('Your account has been verified. Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code. Please try again.')
    else:
        if user.email_sent_at < datetime.utcnow() - timedelta(minutes=5):
            db.session.delete(user)
            db.session.commit()
            flash('Your account has been deleted due to unauthentication of your email for more than 5 minutes.')
            return redirect(url_for('signup'))
    return render_template('verify.html', username=username)

@app.route('/tag/<id>/<tag>', methods=['GET', 'POST'])
def gjfdo(id,tag):
  id = int(id)
  if current_user.is_authenticated:
    dbs(('UPDATE Attachments SET Tags = (?) WHERE ID = (?)',(dbs(('SELECT Tags FROM Attachments WHERE ID = (?)',(id,)),False)[0] + tag,id)),False)
    return 'success'

@app.route('/untag/<id>/<tag>', methods=['GET', 'POST'])
def gjrfdo(id,tag):
  id = int(id)
  if current_user.is_authenticated:
    d = dbs(('SELECT Tags FROM Attachments WHERE ID = (?)',(id,)),False)[0].split(':')
    print(d)
    print(tag)
    d.remove(tag)
    dbs(('UPDATE Attachments SET Tags = (?) WHERE ID = (?)',(':'.join(d),id)),False)
    return 'success'



@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
      flash('To login to a different account, please sign out first.')
      return redirect(url_for('profile'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.email_verified:
            login_user(user)
            if request.args.get('filenext') != None:
              return redirect(f'/file/{request.args.get("filenext")}')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/password-reset-request', methods=['GET', 'POST'])
def password_reset_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.password_reset_token = token
            user.password_reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            message = Message('Password Reset Request', recipients=[email])
            message.body = f'Please click the following link to reset your password: {url_for("password_reset", token=token, _external=True)}'
            mail.send(message)
        else:
          sleep(2)
        flash('An email has been sent if there is an account associated with it.')
    return render_template('password_reset_request.html', form=form)

@app.route('/password-reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    user = User.query.filter_by(password_reset_token=token).first()
    if user and user.password_reset_token_expiry > datetime.utcnow():
        form = PasswordResetForm()
        if form.validate_on_submit():
            user.set_password(form.password.data)
            user.password_reset_token = None
            user.password_reset_token_expiry = None
            db.session.commit()
            flash('Your password has been reset.')
            return redirect(url_for('login'))
        return render_template('test.html', form=form)
    else:
        flash('Invalid or expired password reset token.')
        return redirect(url_for('password_reset_request'))


@app.route('/profile')
@login_required
def profile():
    if current_user.is_authenticated:
      tags = []
      page = request.args.get('page', default=1, type=int)
      per_page = request.args.get('per-page', default=20, type=int)
      offset = (page - 1) * per_page
      if request.args.get('q') == None:
        query = '%'
      else:
        query = request.args.get('q')
        query = '%'+query+'%'
      starfiles = False
      if request.args.get('starred') == 'True':
        starfiles = True
      if request.args.get('order') == 'o-n':
        if request.args.get('starred') is None or request.args.get('starred') == 'False':
          files = array(dbs(('SELECT Permission,Name,Owner,Size,TimeUploaded,ID,Favorites,Tags FROM Attachments WHERE Owner= (?) AND Name LIKE (?)', (current_user.username, query)),True)).tolist()[offset:offset+per_page]
        else:
          files = array(dbs(('SELECT Permission,Name,Owner,Size,TimeUploaded,ID,Favorites,Tags FROM Attachments WHERE Owner= (?) AND Name LIKE (?) AND Favorites = 1', (current_user.username, query)),True)).tolist()[offset:offset+per_page]
        previewlist = []
        for x in files:
          try:
            if request.args['tag'] not in x[7].split(':'):
              print('trying to remove file')
              for i in x[7].split(':')[:-1]:
                if i not in tags:
                  tags.append(i)
              files.remove(x)
          except:
            for i in x[7].split(':')[:-1]:
              if i not in tags:
                tags.append(i)
            filetype = x[1].split(".")[-1]
            if filetype in imagefiletypes or filetype in videofiletypes or filetype in audiofiletypes:
              previewlist.append(True)
            else:
              previewlist.append(False)
        if request.args.get('starred') is None or request.args.get('starred') == 'False':
          total_files = array(dbs(('SELECT COUNT(*) FROM attachments WHERE Owner=(?) AND Name LIKE (?)',(current_user.username, query)),True))[0][0]
        else:
          total_files = array(dbs(('SELECT COUNT(*) FROM attachments WHERE Owner=(?) AND Name LIKE (?) AND Favorites = 1',(current_user.username, query)),True))[0][0]
        total_pages = (total_files + per_page - 1) // per_page
        if query == '%':
          query = '';
        else:
          query = query[1:-1]
        return render_template('profile.html', user=current_user, files=files, empty=[], sizes=[sizeof_fmt(i[3]) for i in files], length=len(files), order='o-n', previewable=previewlist, page=page, per_page=per_page, total_pages=total_pages,offset=offset,total_files=total_files,search=query,star=starfiles,tags=tags)
      else:
        if request.args.get('starred') is None or request.args.get('starred') == 'False':
          files = (array(dbs(('SELECT Permission,Name,Owner,Size,TimeUploaded,ID,Favorites,Tags FROM Attachments WHERE Owner= (?) AND Name LIKE (?)', (current_user.username, query)),True))[::-1]).tolist()[offset:offset+per_page]
        else:
          files = (array(dbs(('SELECT Permission,Name,Owner,Size,TimeUploaded,ID,Favorites,Tags FROM Attachments WHERE Owner= (?) AND Name LIKE (?) AND Favorites = 1', (current_user.username, query)),True))[::-1]).tolist()[offset:offset+per_page]
        previewlist = []
        for x in files:
          try:
            if request.args['tag'] not in x[7].split(':'):
              print('trying to remove file')
              for i in x[7].split(':')[:-1]:
                if i not in tags:
                  tags.append(i)
              files.remove(x)
          except:
            for i in x[7].split(':')[:-1]:
              if i not in tags:
                tags.append(i)
            filetype = x[1].split(".")[-1]
            if filetype in imagefiletypes or filetype in videofiletypes or filetype in audiofiletypes:
              previewlist.append(True)
            else:
              previewlist.append(False)
        if request.args.get('starred') is None or request.args.get('starred') == 'False':
          total_files = array(dbs(('SELECT COUNT(*) FROM attachments WHERE Owner=(?) AND Name LIKE (?)',(current_user.username, query)),True))[0][0]
        else:
          total_files = array(dbs(('SELECT COUNT(*) FROM attachments WHERE Owner=(?) AND Name LIKE (?) AND Favorites = 1',(current_user.username, query)),True))[0][0]
        total_pages = (total_files + per_page - 1) // per_page
        last_file = per_page*page
        if last_file > total_files:
          last_file = total_files
        if query == '*':
          query = '';
        else:
          query = query[1:-1]
        return render_template('profile.html', user=current_user, files=files, empty=[], sizes=[sizeof_fmt(i[3]) for i in files], length=len(files), order='n-o', previewable=previewlist, page=page, per_page=per_page, total_pages=total_pages,last_file=last_file,total_files=total_files,search=query,star=starfiles,tags=tags)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    try:
      session.pop('fileviewkey')
    except:
      pass
    flash('You have been loggzed out.', 'success')
    return redirect(url_for('index'))

class AuthError(Exception):
  pass

uploadingfiles = []
    

@app.route('/change-perm/<id>',methods=["GET","POST"])
def changeperm(id):
  if current_user.is_authenticated:
    try:
      info = dbs(('SELECT Permission, Name, Owner FROM Attachments WHERE ID = (?)',(str(id),)),False)
      if info[2] == current_user.username:
        if info[0] == 0:
          p = 1
        else:
          p = 0
        dbs(("UPDATE Attachments SET Permission = (?) WHERE ID = (?)",(p,id)),False)
        flash(f'Permission changed to {p} for the file {info[1]}')
        if request.args.get('next')=='file':
          return redirect(f"/file/{id}")
        elif request.args.get('next') is not None:
          return redirect(url_for(request.args.get('next')))
        else:
          return "success"
      else:
        flash('You do not have permission to perform this action.')
        if request.args.get('next')=='file':
          return redirect(f"/file/{id}")
        else:
          return redirect(url_for(request.args.get('next')))
    except:
      flash("Error attempting to change file permission")
      if request.args.get('next')=='file':
        return redirect(f"/file/{id}")
      else:
        return redirect(url_for(request.args.get('next')))
  else:
    flash('Login is needed to perform this action')
    return redirect(url_for('login'))

@app.route('/start',methods=["GET","POST"])
def sh():
  global uploadingfiles
  if request.method == 'GET':
    return "<head><title>404 Not Found</title></head><body data-new-gr-c-s-check-loaded='14.1108.0' data-gr-ext-installed=''><h1>404 Not Found</h1><p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p></body>",404
  else:
    print('got start')
    filename = request.headers.get('name')
    if len(filename) > 100:
      filename = filename[:96]+'...'
    lockdiscord.acquire(True)
    response = post(getenv('url')+"?wait=true", data={'thread_name': filename, "content": 'o', 'callback': 'skybox.mea-team.repl.co/callback'})
    try:
      sleep(response.json()['retry_after']+0.1)
    except:
      pass
    lockdiscord.release()
    print('response: '+str(response.status_code))
    if response.status_code == 429:
      print('exceeded in start')
      print(response.status_code)
      print(response.text)
      return 'rate limit exceeded', 403
    try:
      ID = response.json()["id"]
    except:
      print('Errrorrrr, blame discord')
      print(response.status_code)
      print(response.text)
      return 'internal server error', 500
    uploadingfiles.append(ID)
    return ID

@app.route('/upload',methods=['GET',"POST"])
def upload():
  global uploadingfiles
  if request.method == 'POST':
    f = request.headers['fileid']
    if dbs(('SELECT Permission FROM Attachments WHERE ID = (?)',(f,)),True) != 2:
      try:
        if str(f) in uploadingfiles:
          print('uploading chunk for file: '+str(f))
          lockdiscord.acquire(True)
          response = post(getenv('url') + '?thread_id=' + str(f), files={'file': request.data,})
          print('Response from discord: '+str(response.status_code))
          try:
            sleep(response.json()['retry_after']+0.1)
          except:
            pass
          lockdiscord.release()
          if response.ok:
            if request.headers['last'] == "true":
              if request.headers.get('perm') != 2:
                l = request.headers.get('size')
                dbs(('INSERT INTO Attachments VALUES (?,?,?,?,?,?,?,?,?,?)',(int(f),request.headers.get('name'),request.headers.get('uploader'),l,request.headers.get('perm'),datetime.now().strftime("%d/%m/%Y %H:%M:%S"),'N',0,0,'')),False)
              else:
                return 'Wrong endpoint'
              uploadingfiles.remove(f)
            return 'success'
          elif response.status_code == 429:
            print('rate limit hit uploading chunk')
            return 'rate limit', 403
          else:
            print('error with discord api')
            return 'internal error', 500
        else:
          print('id not found: '+f)
          return 'No file found with id', 400
      except Exception as e:
        print('err error in code no idea')
        print(e)
        return 'fail, error in code', 500
    else:
      return 'Wrong permission endpoint!'
  lock.acquire(True)
  c.execute('SELECT COUNT(*) FROM Attachments')
  uploads = str(c.fetchone()[0])
  
  c.execute('SELECT Size FROM Attachments')
  k = 0
  
  for i in c.fetchall():
    k+=i[0]
  l = sizeof_fmt(k)

  usercount = str(User.query.count())
  lock.release()
  try:
    return render_template('upload.html', user=current_user.username, uploadcount = uploads, size = l, usercount = usercount)
  except:
    return render_template('upload.html', user="anonymous", uploadcount = uploads, size = l, usercount = usercount)

encs = {}

#def enc(key,chunk):
#  cipher = threefish(key,key[-16:])
#  if len(chunk)%128 != 0:
#    chunk += b''.join(b'\x00' for i in range((ceil(len(chunk)/128)*128)-len(chunk)))
#  return b''.join([cipher.encrypt_block(chunk[i:i+128]) for i in range(0,len(chunk),128)])

@app.route('/encstart',methods=["GET","POST"])
def swh():
  if request.method == 'GET':
    return "<head><title>404 Not Found</title></head><body data-new-gr-c-s-check-loaded='14.1108.0' data-gr-ext-installed=''><h1>404 Not Found</h1><p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p></body>",404
  else:
    init = b"\xee\xfd\x8f\xcb\\JU\xd9\xc5\x07\xd7aX[\xa1c\x906\x9f\xc2\x04\xe8\x9c\x8b)\xcbz\xdc\xea\xbd\x8d\x0f\xab;\x1byH\xbf\xdbp\xa4\x98k\x125=\x1aI\x0e8\x91\x81\xf3+\x96\xcf?\xb2t\xad\xa6\x065\rU4{\x82\xf3\xf7\xf7\xc2\x87\xd2\x9f\xc7\x81\x9f\r\xb5\xfa%\xb1\xdcq\xa2\xa0%\x92\x8d\nC\x92L\xee\x87\x7fL\xb2M\x01\xb8n\x8f\xe5tUf'\x91\x91n\xa7(\xb0\xb4\xbdx\xa40\x88|[\xab\xdcY\xf4v"
    l = request.data
    print(l)
    op = enc(init,l)
    print(op)
    print(skein1024(init=l).hexdigest())
    response = post(getenv('url')+"?wait=true", data={'thread_name': request.headers.get('name'), "content": skein1024(init=l).hexdigest(), 'callback': 'skybox.mea-team.repl.co/callback'},files={"file":op})
    ID = response.json()["id"]
    dbs(('INSERT INTO Attachments VALUES (?,?,?,?,?,?,?,?,?,?)',(int(ID),request.headers.get('name'),request.headers.get('uploader'),request.headers.get('size'),request.headers.get('perm'),datetime.now().strftime("%d/%m/%Y %H:%M:%S"),'n',0,False)),False)
    encs[int(ID)] = init
    print(init)
    return ID

@app.route('/encupload',methods=['GET',"POST"])
def encupload():
  ID = request.headers["fileid"]
  if request.headers['last'] == 'true':
    print(encs)
    try:
      encs[int(ID)]
    except:
      return 'No file found with ID', 400
    k = request.data
    response = post(getenv('url') + '?thread_id=' + str(ID), files={'file': enc(encs[int(ID)],request.data)},data={"content":f"LAST:{ceil(len(k)/128)*128-len(k)}"})
    del encs[int(ID)]
    print(response.text)
    if response.ok:
      return 'success'
    else:
      return 'fail', 500 
      deletefile(int(ID))
      del encs[int(ID)]
  else:
    response = post(getenv('url') + '?thread_id=' + str(ID), files={'file': enc(encs[int(ID)],request.data),})
    print(response.text)
    if response.ok:
      return 'success'
    else:
      return 'fail', 500 
      deletefile(int(ID))
      del encs[int(ID)]

  return 'success'



@app.route('/create_folder')
def create_folder():
  l = int(open('folder.txt','r').read())
  try:
    f = current_user.username
  except:
    f = 'anonymous'
  dbs(('INSERT INTO Folders VALUES(?,?,?,?)',(l,f,request.headers['name'],dumps([]))),False)
  open('folder.txt','w').write(str(l+1))
  return f'Success ID: {l}'

@app.route('/add/<id>')
def add(id):
  try:
    f = current_user.username
  except:
    f = 'anonymous'
  if dbs(("SELECT owner FROM Folders WHERE id = (?)",(id,)),False) == f:
    dbs(('UPDATE Folders SET list = (?) WHERE ID = (?)',(dumps(pe(dbs(("SELECT list FROM Folders WHERE id = (?)",(id,)),False)) + request.headers['add'],id))),False)
  else:
    return 'Unauthorized'

@app.route('/delete/<id>')
def deletetete(id):
  try:
    f = current_user.username
  except:
    f = 'anonymous'
  if dbs(("SELECT owner FROM Folders WHERE id = (?)",(id,)),False) == f:
    dbs(('DELETE FROM Folders WHERE ID = (?)',(id,)),False)
  else:
    return 'Unauthorized'

@app.route('/file/<id>', methods=['GET', 'POST'])
def retrievefile(id):
  fileinfo = dbs(('SELECT Permission, Owner FROM Attachments WHERE ID = (?)', (id, )),False)
  if fileinfo is None:
    return "Error: file does not exist or deleted."
  permission = fileinfo[0]
  if 0 == permission:
    l = dbs(('SELECT Permission,Name,Owner,Size,TimeUploaded FROM Attachments WHERE ID = (?)',(id, )),False)
    fsize = sizeof_fmt(l[3])
    filetype = l[1].split(".")[-1]
    previewable = False
    if filetype in imagefiletypes or filetype in videofiletypes or filetype in audiofiletypes:
      previewable = True
    return render_template("file_view.html", l=l,id=id,preview=previewable,fsize=fsize)
    #return {"success": True, "file": str(final_str), "name": l[1]}
  elif 1 == permission:
    if current_user.is_authenticated:
      if (current_user.username == fileinfo[1]):
        l = dbs(('SELECT Permission,Name,Owner,Size,TimeUploaded FROM Attachments WHERE ID = (?)',(id, )),False)
        fsize = sizeof_fmt(l[3])
        filetype = l[1].split(".")[-1]
        previewable = False
        if filetype in imagefiletypes or filetype in videofiletypes or filetype in audiofiletypes:
          previewable = True
        return render_template("file_view.html", l=l,id=id,preview=previewable,fsize=fsize)
      else:
        return f"You do not have access to this file. You are logged in as: {current_user.username}<br><a href='/logout'>Change account</a>"
    else:
      flash('Please login to view this file')
      return redirect(url_for('login',filenext=id))
  elif 2 == permission:
    if request.method == "GET":
      return render_template("encrypted_file_access.html")
    else:
      key = request.form['password']
      print(key)
      if key is None:
        flash("Enter your key")
        return redirect(f'/file/{id}')
      slt,passes = dbs(('SELECT Salt, Recurses FROM Attachments WHERE ID = (?)',(id,)),False)
      parts = loads(get(f"https://discord.com/api/v9/channels/{id}/messages/{id}",headers={"Authorization":getenv('Do')}).content.decode("utf-8"))
      print('orig: '+parts['content'])
      init = skein1024(key.encode(),nonce=slt.encode())
      for i in range(passes):
        init = skein1024(init.digest(),nonce=slt.encode())
      init = init.digest()
      print(init)
      #above is correct
      def one28(key,chunk):
        return threefish(key,key[-16:]).decrypt_block(chunk)
      at = one28(init,get(parts["attachments"][0]["url"]).content)
      nk = skein1024(init=at).hexdigest()
      print('new: '+nk)
      if parts['content'] != nk:
        return 'Wrong password!'
      session['fileviewkey'] = key
      l = dbs(('SELECT Permission,Name,Owner,Size,TimeUploaded FROM Attachments WHERE ID = (?)',(id, )),False)
      fsize = sizeof_fmt(l[3])
      filetype = l[1].split(".")[-1]
      previewable = False
      if filetype in imagefiletypes or filetype in videofiletypes or filetype in audiofiletypes:
        previewable = True
      return render_template("file_view.html", l=l,id=id,preview=previewable,fsize=fsize,key=request.form["password"])

@app.route('/download/<id>')
def download_file(id):
  fileinfo = dbs(('SELECT Permission, Owner, Name, Size FROM Attachments WHERE ID = (?)', (id, )),False)
  permission = fileinfo[0]
  size = fileinfo[3]
  def ret():
    if size > 10485760*99:
      first = True
      for i in range(ceil(size/2500006400)):
        if first:
          parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100?",headers={"Authorization":getenv('Do')}).json()[::-1][1:]
          for i in range(99):
            if i == 98:
              before = parts[i]["id"]
              yield get(parts[i]["attachments"][0]["url"]).content
              break
            else:
              yield get(parts[i]["attachments"][0]["url"]).content
          first = False
        else:
          parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100&?after={before}",headers={"Authorization":getenv('Do')}).json()[::-1]
          if parts == []:
            return
          if len(parts) < 100:
            for i in parts:
              yield get(i["attachments"][0]["url"]).content
          else:
            for i in range(len(parts)):
              if i == 99:
                before = parts[i]["id"]
                yield get(parts[i]["attachments"][0]["url"]).content
                break
              else:
                yield get(i["attachments"][0]["url"]).content
    else:
      for i in get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1][1:]:
        yield get(i["attachments"][0]["url"]).content
  if 0 == permission:
    return ret(),{'Content-Disposition': f'attachment; filename={fileinfo[2]}','Content-Type': 'application/octet-stream',}
  elif permission == 2:
    key = session.get('fileviewkey')
    if key is None:
      return redirect(url_for("retrievefile",id=id))
    slt,passes = dbs(('SELECT Salt, Recurses FROM Attachments WHERE ID = (?)',(id,)),False)
    parts = loads(get(f"https://discord.com/api/v9/channels/{id}/messages/{id}",headers={"Authorization":getenv('Do')}).content.decode("utf-8"))
    with open('bruh.txt','w') as file:
      print('original hash:' +parts['content'], file=file)
      print(type(parts['content']), file=file)
    init = b"\xee\xfd\x8f\xcb\\JU\xd9\xc5\x07\xd7aX[\xa1c\x906\x9f\xc2\x04\xe8\x9c\x8b)\xcbz\xdc\xea\xbd\x8d\x0f\xab;\x1byH\xbf\xdbp\xa4\x98k\x125=\x1aI\x0e8\x91\x81\xf3+\x96\xcf?\xb2t\xad\xa6\x065\rU4{\x82\xf3\xf7\xf7\xc2\x87\xd2\x9f\xc7\x81\x9f\r\xb5\xfa%\xb1\xdcq\xa2\xa0%\x92\x8d\nC\x92L\xee\x87\x7fL\xb2M\x01\xb8n\x8f\xe5tUf'\x91\x91n\xa7(\xb0\xb4\xbdx\xa40\x88|[\xab\xdcY\xf4v"
    #above is correct
    def one28(key,chunk):
      return threefish(key,key[-16:]).decrypt_block(chunk)
    at = one28(init,get(parts["attachments"][0]["url"]).content)
    if parts['content'] != skein1024(init=at).hexdigest():
      return 'Wrong password!'
    def dec_block(key,chunk,unpad=0):
      cipher = threefish(key,key[-16:])
      return b''.join([cipher.decrypt_block(chunk[i:i+128])[:-unpad] if i == len(chunk)-128 else cipher.decrypt_block(chunk[i:i+128]) for i in range(0,len(chunk),128)])
    #above is correct
    def enc_ret():
      yield at
      if size > 10485760*99 + 128:
        first = True
        for i in range(ceil(size/2500006400)):
          if first:
            for i in range(100):
              parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1]
              if i == 99:
                before = parts[i]["id"]
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
                break
              else:
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
            first = False
          else:
            parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100&?before={before}",headers={"Authorization":getenv('Do')}).json()[::-1]
            if parts == []:
              return
            if len(parts) < 100:
              for i in range(len(parts)):
                if i == len(parts) - 1 and parts[i]["content"] != '':    
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content,unpad=int(parts[i]["content"].split(':')[1]))
                else:
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
            else:
              for i in range(len(parts)):
                if i == 99 and parts[i]["content"] != '':
                  before = parts[i]["id"]
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content,unpad=int(parts[i]["content"].split(':')[1]))
                  return
                elif i == 99 and parts[i]["content"] == '':
                  before = parts[i]["id"]
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
                  break
                else:
                  yield dec_block(init,get(i["attachments"][0]["url"]).content)
      else:
        f = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1][1:]
        s = len(f)
        for i in range(s):
          if i == s-1:
            yield dec_block(init,get(f[i]["attachments"][0]["url"]).content,unpad=int(f[i]["content"].split(':')[1]))
            break
          else:
            yield dec_block(init,get(f[i]["attachments"][0]["url"]).content)
    return enc_ret(),{'Content-Disposition': f'attachment; filename={fileinfo[2]}','Content-Type': 'application/octet-stream',}
  else:
    if current_user.is_authenticated:
      if (current_user.username == fileinfo[1]):
            return ret(),{'Content-Disposition': f'attachment; filename={fileinfo[2]}','Content-Type': 'application/octet-stream',}
      else:
        return f"You do not have access to this file. You are logged in as: {current_user.username}<br><a href='/logout'>Change account</a>"
    else:
      flash('Please login to download this file')
      return redirect(url_for('login',filenext=id))

@app.route('/delete/<id>', methods=["GET","POST"])
def deletefile(id):
  if request.method == "GET":
    return "Are you sure you want to delete this file?<br><form method='POST'><button type='submit'>Confirm</button> | <a href='javascript:history.go(-1)'>Cancel</a><br>Pro tip: press shift while clicking delete to skip this confirmation"
  if current_user.is_authenticated:
    try:
      owner = dbs(('SELECT Owner FROM Attachments WHERE ID = (?)',(id, )),False)
      if owner[0] == current_user.username:
        f = delete(f'https://discord.com/api/v9/channels/{id}',headers={"Authorization": getenv('Do')})
        dbs(('DELETE FROM Attachments WHERE ID = (?)', (id, )),False)
        if not (request.args.get('supressmessage') == "True"):
          flash('File successfully deleted')
        return redirect(url_for('profile'))
      else:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('profile'))
    except:
      flash("Error attempting to delete file")
      return redirect(url_for('profile'))
  else:
    flash('Login is needed to perform this action')
    return redirect(url_for('login')) 

@app.route('/preview/<id>')
def previewfile(id):
  fileinfo = dbs(('SELECT Permission, Owner, Name, Size FROM Attachments WHERE ID = (?)', (id, )),False)
  filetype = fileinfo[2].split(".")[-1]
  filething = ""
  if filetype in imagefiletypes:
    filething = "image"
  elif filetype in videofiletypes:
    filething = "video"
  elif filetype in audiofiletypes:
    filething = "audio"
  else:
    flash('Filetype not supported for preview')
    return redirect("/file/"+id)
  permission = fileinfo[0]
  size = fileinfo[3]
  def ret():
    #ignore our file size is under it go to the else satemetn
    if size > 25000064*100:
      first = True
      for i in range(ceil(size/2500006400)):
        if first:
          parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100?",headers={"Authorization":getenv('Do')}).json()[::-1][1:]
          for i in range(100):
            if i == 99:
              before = parts[i]["id"]
              yield get(parts[i]["attachments"][0]["url"]).content
              break
            else:
              yield get(parts[i]["attachments"][0]["url"]).content
          first = False
        else:
          parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100&?after={before}",headers={"Authorization":getenv('Do')}).json()[::-1]
          if parts == []:
            return
          if len(parts) < 100:
            for i in parts:
              yield get(i["attachments"][0]["url"]).content
          else:
            for i in range(len(parts)):
              if i == 99:
                before = parts[i]["id"]
                yield get(parts[i]["attachments"][0]["url"]).content
                break
              else:
                yield get(i["attachments"][0]["url"]).content
    else:
      for i in get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1][1:]:
        yield get(i["attachments"][0]["url"]).content

  if 0 == permission:
    bytes = BytesIO()
    bytes.write(list(ret())[0])
    bytes.seek(0)
    if filething == "image":
      return send_file(bytes, 'image/'+filetype, as_attachment=False)
    elif filething == "video":
      video_base64 = base64.b64encode(bytes.read()).decode('utf-8')
      return f"""<p style="position: absolute;">Loading...</p><video width="320" height="240" controls style="position: absolute; transform: translate(-10px, -15px);">
  <source src="data:video/{filetype};base64,{video_base64}" type="{filething}/{filetype}">
Your browser does not support the video tag.
</video>"""
    elif filething == "audio":
      audio_base64 = base64.b64encode(bytes.read()).decode('utf-8')
      if filetype == "mp3":
        filetype = "mpeg"
      return f"""<p style="position: absolute;">Loading...</p><audio controls style="position: absolute;">
<source src="data:audio/{filetype};base64,{audio_base64}" type="audio/{filetype}">
Your browser does not support the audio tag.
</audio>"""
  elif permission == 2:
    key = session.get('fileviewkey')
    if key is None:
      return redirect(url_for("retrievefile",id=id))
    slt,passes = dbs(('SELECT Salt, Recurses FROM Attachments WHERE ID = (?)',(id,)),False)
    parts = loads(get(f"https://discord.com/api/v9/channels/{id}/messages/{id}",headers={"Authorization":getenv('Do')}).content.decode("utf-8"))
    #then I implemnt the bonky house theorem in order to have maximum security hi my name is raine ma if you are reading this I will hack into your email and steal all of your personal infromation and tehen pose as you on social meedia then proceeed to steal your identity and everytihng you own.
    init = skein1024(key.encode(),nonce=slt.encode())
    for i in range(passes):
      init = skein1024(init.digest(),nonce=slt.encode())
    init = init.digest()
    #above is correct
    def one28(key,chunk):
      return threefish(key,key[-16:]).decrypt_block(chunk)
    at = one28(init,get(parts["attachments"][0]["url"]).content)
    if parts['content'] != skein1024(init=at).hexdigest():
      return 'Wrong password!'
    def dec_block(key,chunk,unpad=0):
      cipher = threefish(key,key[-16:])
      return b''.join([cipher.decrypt_block(chunk[-128:])[:-unpad] if i == len(chunk)-128 else cipher.decrypt_block(chunk[i:i+128]) for i in range(0,len(chunk),128)])
    #above is correct
    def enc_ret():
      yield at
      if size > 25000064*99 + 128:
        first = True
        for i in range(ceil(size/2500006400)):
          if first:
            for i in range(100):
              parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1]
              if i == 99:
                before = parts[i]["id"]
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
                break
              else:
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
            first = False
          else:
            parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100&?before={before}",headers={"Authorization":getenv('Do')}).json()[::-1]
            if parts == []:
              return
            if len(parts) < 100:
              for i in range(len(parts)):
                if i == len(parts) - 1 and parts[i]["content"] != '':    
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content,unpad=int(parts[i]["content"].split(':')[1]))
                else:
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
            else:
              for i in range(len(parts)):
                if i == 99 and parts[i]["content"] != '':
                  before = parts[i]["id"]
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content,unpad=int(parts[i]["content"].split(':')[1]))
                  return
                elif i == 99 and parts[i]["content"] == '':
                  before = parts[i]["id"]
                  yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
                  break
                else:
                  yield dec_block(init,get(i["attachments"][0]["url"]).content)
      else:
        f = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1][1:]
        s = len(f)
        for i in range(s):
          if i == s-1:
            yield dec_block(init,get(f[i]["attachments"][0]["url"]).content,unpad=int(f[i]["content"].split(':')[1]))
          else:
            yield dec_block(init,get(f[i]["attachments"][0]["url"]).content)
    bytes = BytesIO()
    bytes.write(b''.join(list(enc_ret())))
    bytes.seek(0)
    if filething == "image":
      return send_file(bytes, 'image/'+filetype, as_attachment=False)
    elif filething == "video":
      video_base64 = base64.b64encode(bytes.read()).decode('utf-8')
      return f"""<p style="position: absolute;">Loading...</p><video width="320" height="240" controls style="position: absolute; transform: translate(-10px, -15px);">
  <source src="data:video/{filetype};base64,{video_base64}" type="{filething}/{filetype}">
Your browser does not support the video tag.
</video>"""
    elif filething == "audio":
      audio_base64 = base64.b64encode(bytes.read()).decode('utf-8')
      if filetype == "mp3":
        filetype = "mpeg"
      return f"""<p style="position: absolute;">Loading...</p><audio controls style="position: absolute;">
<source src="data:audio/{filetype};base64,{audio_base64}" type="audio/{filetype}">
Your browser does not support the audio tag.
</audio>"""
  else:
    if current_user.is_authenticated:
      if (current_user.username == fileinfo[1]):
        bytes = BytesIO()
        bytes.write(list(ret())[0])
        bytes.seek(0)
        if filething == "image":
          return send_file(bytes, 'image/'+filetype, as_attachment=False)
        elif filething == "video":
          video_base64 = base64.b64encode(bytes.read()).decode('utf-8')
          return f"""<p style="position: absolute;">Loading...</p><video width="320" height="240" controls style="position: absolute; transform: translate(-10px, -15px);">
      <source src="data:video/{filetype};base64,{video_base64}" type="{filething}/{filetype}">
    Your browser does not support the video tag.
    </video>"""
        elif filething == "audio":
          audio_base64 = base64.b64encode(bytes.read()).decode('utf-8')
          if filetype == "mp3":
            filetype = "mpeg"
          return f"""<p style="position: absolute;">Loading...</p><audio controls style="position: absolute;">
    <source src="data:audio/{filetype};base64,{audio_base64}" type="audio/{filetype}">
    Your browser does not support the audio tag.
    </audio>"""
      else:
        return f"You do not have access to this file. You are logged in as: {current_user.username}<br><a href='/logout'>Change account</a>"
    else:
      flash('Please login to preview this file')
      return redirect(url_for('login',filenext=id))

@app.route('/favorite/<id>',methods=["GET","POST"])
def favoritefile(id):
  if current_user.is_authenticated:
    owner = dbs(('SELECT Owner FROM Attachments WHERE ID = (?)',(id,)),False)[0]
    if owner == current_user.username:
      k = (dbs(("SELECT Favorites FROM Attachments WHERE ID = (?)",(id,)),False)[0])
      print(k)
      dbs(("UPDATE Attachments SET Favorites = (?) WHERE ID = (?)",((not k),id)),False)
      print(dbs(("SELECT Favorites FROM Attachments WHERE ID = (?)",(id,)),False)[0])
      
      return 'Success'
    else:
      return f"You do not have permission do perform this action. You are logged in as: {current_user.username}"
  else:
    flash('Please login to favorite this file')
    return redirect(url_for('login'))

@app.route('/admin')
def adminpanel():
  if not current_user.is_authenticated:
    return "<head><title>404 Not Found</title></head><body data-new-gr-c-s-check-loaded='14.1108.0' data-gr-ext-installed=''><h1>Not Found</h1><p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p></body>",404
  if not(current_user.username in ['432mea','433MEA']):
    return "<head><title>404 Not Found</title></head><body data-new-gr-c-s-check-loaded='14.1108.0' data-gr-ext-installed=''><h1>Not Found</h1><p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p></body>",404
  else:
    c.execute('SELECT COUNT(*) FROM Attachments')
    uploads = str(c.fetchone()[0])
    
    c.execute('SELECT Size FROM Attachments')
    k = 0
    
    for i in c.fetchall():
      k+=i[0]
    l = sizeof_fmt(k)

    usercount = str(User.query.count())

    with open("totalrequests.txt", 'r') as fp:
      requestcount = fp.read()
    
    return render_template('admin.html', uploads = uploads, size = l, usercount = usercount, requestcount = requestcount)

@app.route('/filesgraph')
def home():
  c.execute("SELECT Timeuploaded FROM Attachments")
  data = c.fetchall()
  day_counts = {}
  for y in data:
      timeuploaded = y[0]
      day = timeuploaded.split()[0]
      day_counts[day] = day_counts.get(day, 0) + 1

  day_counts = list(day_counts.items())
  num = 0
  filedata = []

  for i in day_counts:
    filedata.append((i[0], int(i[1]) + num))
    num = int(i[1])+num

  labels = [row[0] for row in filedata]
  values = [row[1] for row in filedata]

  return render_template('graph.html', labels=labels, values=values)

@app.after_request
def after_request(response):
    with open('totalrequests.txt','r') as f:
      if f.read == '':
        count = 0
      else:
        count = int(f.read())
    with open('totalrequests.txt','w') as f:
      f.write(str(count+1))
    if 'OPTIONS' == request.method or 'HEAD' == request.method or 'POST' == request.method:
      return response
    timestamp = strftime('[%Y-%b-%d %H:%M]')
    logger.error('%s %s %s %s %s %s', timestamp, request.remote_addr, request.method, request.scheme, request.full_path, response.status)
    return response

app.add_url_rule("/download/<id>", endpoint="download_file", build_only=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
    logger = logging.getLogger('tdm')
    logger.setLevel(logging.ERROR)
    logger.addHandler(handler)
    app.run(debug=False, host='0.0.0.0')