from flask import Flask, render_template, session, request, url_for, flash, redirect
import config 
import sqlite3 
import uuid
import hash

app = Flask(__name__)

app.config.from_object('config')

@app.route('/', methods=['GET','POST'])
def start():
    if 'failed_logins' not in session:
        session['failed_logins'] = 0
    return redirect(url_for('login'), 307)

#resets failed login attempts
#hackers ignore this!!!!!
@app.route('/veryveryhidden', methods=['GET','POST'])
def super_secrete_reset_method():
    session['failed_logins'] = 0
    db = sqlite3.connect(config.CREDENTIALS_FILE)
    db.execute("UPDATE users SET locked = 0, failed_attempts = 0 ")
    db.commit()
    db.close()
    return redirect(url_for('login'), 307)


@app.route('/login', methods=['GET','POST'])
def login():
    #failed login attempts not tied to a user so will not lock any accounts
    
    if session['failed_logins'] > config.MAX_ATTEMPTS:
        return redirect(url_for('locked_out'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        attempted_password = request.form.get('password')

        """
        fetches hashed password linked with <username> 
        if no username matching <username> is found then the session failed_logins will be incremented
        if a username matching <username> is found but the password is incorrect then the session failed_logins and the 
        account in the db will have failed logins incremented  

        A successful login will reset the failed attempts in the session and db
        """
        try:
            db = sqlite3.connect(config.CREDENTIALS_FILE)
            row = db.execute("SELECT id, password,locked,failed_attempts FROM users WHERE username = ?;",(username,)).fetchone()
            if row:
                user_id, recorded_password, locked, failed_attempts = row
            else:
                session['failed_logins'] += 1
                print(f"session fails: {session['failed_logins']}")
                flash("Username or Password are incorrect")
                

            if locked:
                return redirect(url_for('locked_out'))

            if hash.authenticate(recorded_password,attempted_password): 
                session['failed_logins'] = 0 #reset failed login attemtps
                db.execute("UPDATE users SET failed_attempts = 0 WHERE id == ?",(user_id,))
                db.commit()
                db.close()
                session['user_id'] = user_id
                return redirect(url_for('home',id_=user_id))
            else:
                
                if failed_attempts >= config.MAX_ATTEMPTS or session['failed_logins'] >= config.MAX_ATTEMPTS:
                    db.execute("UPDATE users SET locked = 1 WHERE id == ?",(user_id,))
                    db.commit()
                    db.close()
                    return redirect(url_for('locked_out'))
                
                session['failed_logins'] += 1
                print(session['failed_logins'],failed_attempts)
                db.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id == ?",(user_id,))
                db.commit()
                flash("Username or Password are incorrect")
                db.close()
        except:
            flash("Username or Password are incorrect")
        
    return render_template('login.html',
                           title="Login Page",
                           heading="Login Page")

#user lockout screen
@app.route('/locked_out', methods=['GET'])
def locked_out():
    return render_template('locked.html',
                           title="Locked out")


"""
User creation checks for username validity in this function and 
password validity in the html file using js 
resets failed login attempts if an account is created
"""
@app.route('/user_creation', methods=['GET','POST'])
def create_user():
    if request.method == 'POST':
        db = sqlite3.connect(config.CREDENTIALS_FILE)
        username = request.form.get('username')
        password = request.form.get('password').strip()


        #password validation is handled using js in user_creation.html

        username_is_taken = any(db.execute("SELECT username FROM users WHERE username == ?",(username,)))
        if username != username.strip():
            flash("No spaces in your username or password")
        elif username_is_taken:
            flash("Username is already taken!",'alert-danger')
        else:
            try:
                user_id = str(uuid.uuid4())
                hashed_password = hash.hash_pw(password)

                db.execute("INSERT INTO users (id,username,password,permissions,locked,failed_attempts) VALUES (?,?,?,3,0,0)",
                           (user_id,username,hashed_password,))
                db.commit()
                db.close()

                #reset session failed logins to prevent issues
                if 'failed_logins' in session:
                    session['failed_logins'] = 0
                session['user_id'] = user_id
                return redirect(url_for('home',id_=user_id))
            except ValueError:
                print(ValueError)
                print("SQL query failed")
                return render_template("user_creation.html")
    return render_template("user_creation.html")


@app.route('/home/<string:id_>', methods=['GET'])
def home(id_):
    id_ = session.get('user_id')
    if not id_:
        return redirect(url_for('login'))
    db = sqlite3.connect(config.CREDENTIALS_FILE)
    row = db.execute("SELECT username, permissions FROM users WHERE id == ?",(id_,)).fetchone()
    if row:
        username, perms = row
    
    permission_type = ''
    if perms <= 1:
        permission_type = 'admin'
    elif perms == 2:
        permission_type = 'eng'
    else:
        permission_type = 'user'

    return render_template('home.html',user_id=id_,user=username,type=permission_type)

@app.route('/user/search', methods=['GET'])
def user_search():
    session.get('user_id')
    perms = ""
    return render_template('search.html',type=perms)

@app.route('/engineer/search', methods=['GET'])
def eng_search(perms_,id_):
    
    #locks out users who access restricted info
    if perms_ > 2:
        db = sqlite3.connect(config.CREDENTIALS_FILE)
        db.execute("UPDATE users SET locked = 1 WHERE id == ?",(id_,))
        db.commit()
        db.close()
        return redirect(url_for('locked_out'))
    
    return render_template('search.html',type=perms_,id=id_)

@app.route('/admin/search', methods=['GET'])
def adm_search(perms_,id_):

    return render_template('search.html',type=perms_)


if __name__ == "__main__":
    app.run(port=12345)