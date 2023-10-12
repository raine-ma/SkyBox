from flask import Flask, request, render_template, send_file, redirect, url_for
from os import getenv
from sqlite3 import connect
from hashlib import sha512
import traceback
import uuid
from json import loads
from requests import get
from werkzeug.utils import secure_filename
from io import BytesIO
from datetime import datetime
from smtplib import SMTP
from email.mime.text import MIMEText
import secrets # bruh I was uploading a 2 gb file. um oops did i mess it up? sorry also once it uploads can you put the link here so I can see
from time import time

#Backend completed

#TODO:
# Add recover password
# list files each user has on a profile page - in progress
#    add delete file function
# ability to add password to files
# make everything run faster and more efficient
# make landing page and ui stuff
#    progress bar

app = Flask(__name__)

UPLOAD_FOLDER = '/downloads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class AuthError(Exception):
  pass


@app.route('/delete/<fileid>')
def delete_file(fileid):
  from requests import delete
  conn = connect('database.db')
  c = conn.cursor()
  c.execute('SELECT Loc FROM Attachments WHERE ID = (?)', (fileid, ))
  delete(f"https://discord.com/api/v9/channels/{c.fetchone()[0]}")


@app.route('/')
def main():
  return render_template('home.html')

@app.route('/verify', methods=['GET','POST'])
def verify():
  name = request.args.get('username')
  pwd = request.args.get('pword')
  email = request.args.get('email')
  tok = request.args.get('tok')
  pnum = request.args.get('phonenum')
  code = tok[:6]
  if request.method == 'POST':
    if not (request.form['vcode'] == code):
      return "Wrong code. Try again: <a href='javascript:history.back()''>Go Back</a>"
    conn = connect('database.db')
    c = conn.cursor()
    c.execute('SELECT name FROM Users WHERE name = (?)',(name,))
    if c.fetchone() == None:
      if (len(name) > 20):
        s = f'Username too long. Limit 20 chars for username ({len(name)} entered)'
        return s
      elif ':' in name or ' ' in name or '/' in name:
        s = 'Characters (:,/) and spaces not allowed in names'
        return s
      if pnum=="":
        authphone = 0
      else:
        authphone = 1
      c.execute('INSERT INTO Users VALUES (?,?,?,?,?,?,?,?,?)',(name,pwd,tok,0,int(time()),email,pnum,1,authphone))
      conn.commit()
      return {"success": True}
    else:
      s = 'User already exists!'
      return s

  
  class RegistrationError(Exception):
    pass
  try:
    msg = MIMEText(f'Your SkyBox Verification Code is: {code}')
    msg['From'] = 'SkyBox'
    msg['To'] = email
    msg['Subject'] = 'SkyBox Verification'
    server = SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('skyboxcloud0@gmail.com', 'lttpxwrceryoqsnh')
    server.sendmail('skyboxcloud0@gmail.com', email, msg.as_string())
    server.quit()
    return render_template('verify.html')
  except Exception as e:
    return {"success": False, "message": str(e)}


@app.route('/sign-up',methods=['GET','POST'])
def register():
  if request.method == 'POST':
    name, pwd, email = request.form['username'],request.form['pswd'],request.form['email']
    if email == '' or name == '' or pwd == '':
      s = 'Fill out all required fields!'
      return s
    conn = connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM Users WHERE name = (?)',(request.form['username'],))
    if c.fetchone() == None:
      if (len(name) > 20 or len(pwd) > 100):
        s = f'Username or password too long limit 20 chars for username ({len(name)} entered) and 100 for password ({len(pwd)} entered'
        return s
      elif ':' in name or ' ' in name or '/' in name:
        s = 'Characters (:,/) and spaces not allowed in names'
        return s
    else:
      s = "Username already taken"
      return s

    c.execute('SELECT * FROM Users WHERE Email = (?)',(request.form['email'],))
    if not (c.fetchone() == None):
      s = 'Email already in use'
      return s
    token = secrets.token_urlsafe(64)
    return redirect(url_for('verify', username=request.form['username'], tok = token, pword = sha512((request.form['pswd']+token).encode()).hexdigest(), email = request.form['email'], phonenum = request.form['pnum']))
  return render_template('signup.html')


ID = ""


@app.route('/upload',methods=['GET',"POST"])
def upload():
  if request.method == 'POST':
    keys = [key for key,val in request.form.items()]
    values = [val for key,val in request.form.items()]
    if values[keys.index('username')] == '':
      values[keys.index('username')] = 'anonymous'
      values[keys.index('pswd')] = 'anonymous'
      values[keys.index('permission')] = 'PUBLIC'
    if values[keys.index('username')] == 'anonymous':
      values[keys.index('permission')] = 'PUBLIC'
    try:
      def uploadworker(permission,file,user):
        from requests import post
        from json import loads
        from os import fstat
        chunk_size = 25000000
        webhook_url = 'https://discord.com/api/webhooks/1097675748199891024/fkHasYKKOUKlMn3ekgBtVusj2OUmtTS2Onnw7HJRbez7O7k5tuqcFGkmi23MD3pSasYH'
        if (k := fstat((file).fileno()).st_size) > 0:
          pass
        if (num_chunks := (k + chunk_size - 1) // chunk_size) > 0:
          pass
        first = True
      
        for i in range(num_chunks):
          file.filename = secure_filename(file.filename)
          if len(file.filename) > 50:
              return "File name too long. Max: 50 characters"
          else:
            if first:
              global ID
              ID = str(uuid.uuid4())
              response = post(webhook_url, data={'thread_name': f"{ID}"}, files={'file': file.read(chunk_size),})
              file.seek((i+1)*chunk_size)
              loc = loads(response.text)["id"]
              webhook_url2 = webhook_url + '?thread_id=' + loc
              first = False
            else:
              response = post(webhook_url2, files={'file': file.read(chunk_size),})
              file.seek((i+1)*chunk_size)
        conn1 = connect('database.db')
        c1 = conn1.cursor()
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        c1.execute('INSERT INTO Attachments VALUES (?,?,?,?,?,?,?)',(ID,loc,file.filename,user,k,permission,dt_string))
        conn1.commit()
      conn = connect('database.db')
      c = conn.cursor()
      c.execute('SELECT PwdHash, Salt from Users WHERE name = (?)',(values[keys.index('username')],))
      k = c.fetchone()
      if k == None:
        return 'User does not exist.'
      if not (sha512((values[keys.index('pswd')]+k[1]).encode()).hexdigest() == k[0]):
        return 'Invalid Username or Password, Try again.'
      result = uploadworker(values[keys.index('permission')],request.files['file'],values[keys.index('username')])
      if result == "File name too long. Max: 35 characters":
        return "File name too long. Max: 35 characters"
      return {"success": True, "ID": ID, "File link": f"https://skybox.mea-team.repl.co/file/{ID}"}
    except Exception as e:
      traceback.print_exc()
      return {"success": False, "message": str(e)}
  return render_template('upload.html')


@app.route('/file/<id>', methods=['GET', 'POST'])
def retrievefile(id):
  if request.method == "POST":
    try:
      user = request.form['username']
      password = request.form['pswd']
      conn = connect('database.db')
      c = conn.cursor()
      c.execute(
        'SELECT Permission,Name,Owner,Size,TimeUploaded FROM Attachments WHERE ID = (?)',
        (id, ))
      l = c.fetchone()
      if not (l[0] == 'PUBLIC'):
        conn = connect('database.db')
        c = conn.cursor()
        c.execute('SELECT PwdHash, Salt from Users WHERE name = (?)',
                  (request.form['username'], ))
        k = c.fetchone()
        if k == None:
          return 'User does not exist.'
        password = sha512((password + k[1]).encode()).hexdigest()
        if not (password == k[0]):
          s = 'Invalid username/password or you are not registered.'
          raise AuthError(s)
        final_str = b''
        c.execute('SELECT Loc FROM Attachments WHERE ID = (?)', (id, ))
        for i in loads(
            get(
              f"https://discord.com/api/v9/channels/{c.fetchone()[0]}/messages",
              headers={
                "Authorization":
                'Bot MTA5ODAzNTAxMjcyMjQ5MTQwMg.G3VJO4.QL-snBP72sHnEcC0A3DeUIh0gOTnxJl9mqkqRg'
              }).text):
          final_str += get(i["attachments"][0]["url"]).content
        return f"""<h1>{l[1]}</h1><br><p>Uploaded by: {l[2]}</p><br><p>File size: {l[3]} bytes</p><br><p>Date uploaded: {l[4]} GMT</p><br><p><a href='https://skybox.mea-team.repl.co/download/{id}/{user}/{password}' target="_blank">Download</a></p>"""
        #return {"success": True, "file": str(final_str), "name": l[1]}
      else:
        final_str = b''
        c.execute('SELECT Loc FROM Attachments WHERE ID = (?)', (id, ))
        for i in loads(
            get(
              f"https://discord.com/api/v9/channels/{c.fetchone()[0]}/messages",
              headers={
                "Authorization":
                'Bot MTA5ODAzNTAxMjcyMjQ5MTQwMg.G3VJO4.QL-snBP72sHnEcC0A3DeUIh0gOTnxJl9mqkqRg'
              }).text):
          final_str += get(i["attachments"][0]["url"]).content
        return f"""<h1>{l[1]}</h1><br><p>Uploaded by: {l[2]}</p><br><p>File size: {l[3]} bytes</p><br><p>Date uploaded: {l[4]} GMT</p><br><p><a href='https://skybox.mea-team.repl.co/download/{id}/{user}/{password}' target="_blank">Download</a></p>"""
        #return {"success": True, "file": str(final_str), "name": l[1]}
    except Exception as e:
      traceback.print_exc()
      return {"success": False, "message": str(e)}

  conn = connect('database.db')
  c = conn.cursor()
  c.execute('SELECT Permission FROM Attachments WHERE ID = (?)', (id, ))
  permission = c.fetchone()
  permission = permission[0]
  if 'PUBLIC' == permission:
    try:
      user = "anonymous"
      conn = connect('database.db')
      c = conn.cursor()
      c.execute(
        'SELECT Permission,Name,Owner,Size,TimeUploaded FROM Attachments WHERE ID = (?)',
        (id, ))
      l = c.fetchone()
      conn = connect('database.db')
      c = conn.cursor()
      c.execute('SELECT Loc FROM Attachments WHERE ID = (?)', (id, ))
      final_str = b''
      for i in loads(
          get(
            f"https://discord.com/api/v9/channels/{c.fetchone()[0]}/messages",
            headers={
              "Authorization":
              'Bot MTA5ODAzNTAxMjcyMjQ5MTQwMg.G3VJO4.QL-snBP72sHnEcC0A3DeUIh0gOTnxJl9mqkqRg'
            }).text):
        final_str += get(i["attachments"][0]["url"]).content
      return f"""<h1>{l[1]}</h1><br><p>Uploaded by: {l[2]}</p><br><p>File size: {l[3]} bytes</p><br><p>Date uploaded: {l[4]} GMT</p><br><p><a href='https://skybox.mea-team.repl.co/download/{id}/anonymous/anonymous' target="_blank">Download</a></p>"""
      #return {"success": True, "file": str(final_str), "name": l[1]}
    except Exception as e:
      traceback.print_exc()
      return {"success": False, "message": str(e)}
  else:
    return render_template('fileview.html')


@app.route('/download/<id>/<user>/<password>')
def download_file(id, user, password):
  conn = connect('database.db')
  c = conn.cursor()
  c.execute('SELECT Permission,Name FROM Attachments WHERE ID = (?)', (id, ))
  permission = c.fetchone()
  filename = permission[1]
  permission = permission[0]
  if 'PUBLIC' == permission:
    conn = connect('database.db')
    c = conn.cursor()
    c.execute('SELECT Loc FROM Attachments WHERE ID = (?)', (id, ))
    final_str = b''
    for i in loads(
        get(
          f"https://discord.com/api/v9/channels/{c.fetchone()[0]}/messages",
          headers={
            "Authorization":
            'Bot MTA5ODAzNTAxMjcyMjQ5MTQwMg.G3VJO4.QL-snBP72sHnEcC0A3DeUIh0gOTnxJl9mqkqRg'
          }).text):
      final_str += get(i["attachments"][0]["url"]).content
    file_obj = BytesIO()
    file_obj.write(final_str)
    file_obj.seek(0)
    return send_file(file_obj, download_name=filename, as_attachment=True)
  else:
    conn = connect('database.db')
    c = conn.cursor()
    c.execute('SELECT PwdHash, Salt from Users WHERE name = (?)', (user, ))
    k = c.fetchone()
    if k == None:
      return 'User does not exist.'
    if not (password == k[0]):
      s = 'Invalid username/password or you are not registered.'
      raise AuthError(s)
    final_str = b''
    c.execute('SELECT Loc FROM Attachments WHERE ID = (?)', (id, ))
    for i in loads(
        get(
          f"https://discord.com/api/v9/channels/{c.fetchone()[0]}/messages",
          headers={
            "Authorization":
            'Bot MTA5ODAzNTAxMjcyMjQ5MTQwMg.G3VJO4.QL-snBP72sHnEcC0A3DeUIh0gOTnxJl9mqkqRg'
          }).text):
      final_str += get(i["attachments"][0]["url"]).content
    file_obj = BytesIO()
    file_obj.write(final_str)
    file_obj.seek(0)
    return send_file(file_obj, download_name=filename, as_attachment=True)

app.add_url_rule("/download/<id>/<user>/<password>",
                 endpoint="download_file",
                 build_only=True)
app.run(host='0.0.0.0', port='8080')

#c.execute('INSERT INTO Users VALUES (?,?,?,?,?,?)')