from flask import Flask, render_template, request, url_for, flash, redirect
import config 
import sqlite3 
import uuid

app = Flask(__name__)

app.config.from_object('config')

@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        #check db
        print(f"{username},{password}")
        if True: #TODO replace with db check
            return redirect('http://127.0.0.1:12345/home')
    return render_template('login.html',
                           title="Login Page",
                           heading="Login Page")


@app.route('/user_creation', methods=['GET','POST'])
def create_user():
    db = sqlite3.connect(config.CREDENTIALS_FILE)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password') #password validation is handled using js in user_creation.html

        username_is_taken = any(db.execute(f"SELECT username FROM users WHERE username == '{username}'"))

        if username_is_taken:
            flash("Username is already taken!",'alert-danger')
        else:
            try:
                user_id = str(uuid.uuid4())
                db.execute(f"INSERT INTO users (id,username,password,permissions) VALUES ('{user_id}','{username}','{password}',3)")
                db.commit()
                db.close()
                return redirect(url_for('/home',id_=user_id))
            except:
                return "<Account Creation failed>"
    return render_template("user_creation.html")


@app.route('/home/<string:id_>', methods=['GET'])
def home(id_):
    return render_template('home.html')

if __name__ == "__main__":
    app.run(port=12345)