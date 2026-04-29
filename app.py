from flask import Flask, render_template, request, url_for, flash, redirect
import config 
import sqlite3 
import uuid
import hash

app = Flask(__name__)

app.config.from_object('config')

@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        attempted_password = request.form.get('password')

        db = sqlite3.connect(config.CREDENTIALS_FILE)

        #fetches hashed password linked with <username>
        row = db.execute("SELECT id, password FROM users WHERE username = ?;",(username,)).fetchone()
        if row:
            user_id, recorded_password = row
        db.close()

        if hash.authenticate(recorded_password,attempted_password): 
            return redirect(url_for('home',id_=user_id))
        
    return render_template('login.html',
                           title="Login Page",
                           heading="Login Page")


@app.route('/user_creation', methods=['GET','POST'])
def create_user():
    db = sqlite3.connect(config.CREDENTIALS_FILE)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password') #password validation is handled using js in user_creation.html

        username_is_taken = any(db.execute("SELECT username FROM users WHERE username == ?",(username,)))

        if username_is_taken:
            flash("Username is already taken!",'alert-danger')
        else:
            try:
                user_id = str(uuid.uuid4())
                hashed_password = hash.hash_pw(password)

                db.execute(f"INSERT INTO users (id,username,password) VALUES ('{user_id}','{username}','{hashed_password}',3)")
                db.commit()
                db.close()
                return redirect(url_for('home',id_=user_id))
            except:
                return render_template("user_creation.html")
    return render_template("user_creation.html")


@app.route('/home/<string:id_>', methods=['GET'])
def home(id_):
    db = sqlite3.connect(config.CREDENTIALS_FILE)
    row = db.execute("SELECT username, permissions FROM users WHERE id == ?",(id_,)).fetchone()
    if row:
        username, perms = row
    
    return render_template('home.html',user_id=id_,user=username,permissions=perms)

@app.route('/search/<string:perms_>', methods=['GET'])
def search(perms_):
    query = request.args.get('query')
    if query:
        db = sqlite3.connect(config.DB_FILE)
        
    return render_template('search.html',type=perms_)

if __name__ == "__main__":
    app.run(port=12345)