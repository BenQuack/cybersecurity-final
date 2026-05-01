from flask import Flask, render_template, session, request, url_for, flash, redirect
import config 
import sqlite3 
import uuid
import hash
import re

app = Flask(__name__)

app.config.from_object('config')

@app.route('/', methods=['GET','POST'])
def start():
    if 'failed_logins' not in session:
        session['failed_logins'] = 0
    return redirect(url_for('login'), 302)

#resets failed login attempts
#hackers ignore this!!!!!
#would never ever ever include this in an actual app
@app.route('/veryveryhidden', methods=['GET','POST'])
def super_secret_reset_method():
    session.clear()
    db = sqlite3.connect(config.CREDENTIALS_FILE)
    db.execute("UPDATE users SET locked = 0, failed_attempts = 0 ")
    db.commit()
    db.close()
    return redirect(url_for('login'), 302)


@app.route('/login', methods=['GET','POST'])
def login():
    #failed login attempts not tied to a user so will not lock any accounts
    
    if session.get('failed_logins', 0) > config.MAX_ATTEMPTS:
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
        db = None
        try:
            db = sqlite3.connect(config.CREDENTIALS_FILE)
            row = db.execute("SELECT id, password,locked,failed_attempts FROM users WHERE username = ?;",(username,)).fetchone()
            if row:
                user_id, recorded_password, locked, failed_attempts = row
            else:
                session['failed_logins'] += 1
                print(session['failed_logins'])
                flash("Username or Password are incorrect")
                return render_template('login.html',
                           title="Login Page",
                           heading="Login Page")
                                

            if locked:
                return redirect(url_for('locked_out'))

            if hash.authenticate(recorded_password,attempted_password): 
                session['failed_logins'] = 0 #reset failed login attempts
                db.execute("UPDATE users SET failed_attempts = 0 WHERE id == ?",(user_id,))
                db.commit()
                session['user_id'] = user_id
                return redirect(url_for('home',id_=user_id))
            else:
                
                if failed_attempts >= config.MAX_ATTEMPTS or session.get('failed_logins') >= config.MAX_ATTEMPTS:
                    db.execute("UPDATE users SET locked = 1 WHERE id == ?",(user_id,))
                    db.commit()
                    return redirect(url_for('locked_out'))
                
                session['failed_logins'] += 1
                db.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id == ?",(user_id,))
                db.commit()
                flash("Username or Password are incorrect")
        except Exception as e:
            print(f"An unknown error {e} as occured please contact an administrator")
            flash("Username or Password are incorrect")

        finally:
            if db:
                db.close()
        
    return render_template('login.html',
                           title="Login Page",
                           heading="Login Page")


@app.route('/logout',methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))

#user lockout screen
@app.route('/locked_out', methods=['GET'])
def locked_out():
    return render_template('locked.html',
                           title="Locked out")



def validate_password(password: str) -> list[str]:
    """
    Validates password against required security criteria.
    Returns a list of error messages; empty list means password is valid.
    """


    errors = []
    special = r"!@#$%^&*()_+\-=\[\]{}|;':\",./<>?"

    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if len(password) > 25:
        errors.append("Password must be no more than 25 characters.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")
    if not re.search(f"[{special}]", password):
        errors.append("Password must contain at least one special character.")
    if re.search(r"\s", password):
        errors.append("Password must not contain spaces.")

    return errors

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
        password = request.form.get('password')


        errors = validate_password(password)
        for error in errors:
            flash(error, 'alert-danger')
        if errors:
            return render_template('user_creation.html')
        
        if username != username.strip():
            flash("No spaces in your username or password")
            return render_template('user_creation.html')

        username_is_taken = any(db.execute("SELECT username FROM users WHERE username == ?",(username,)))
        
        
        if username_is_taken:
            flash("Username is already taken!",'alert-danger')
            return render_template('user_creation.html')
        
        try:
            user_id = str(uuid.uuid4())
            hashed_password = hash.hash_pw(password)

            db.execute(
                    "INSERT INTO users (id, username, password, permissions, locked, failed_attempts) "
                    "VALUES (?,?,?,?,?,?)",
                    (user_id, username, hashed_password, 3, 0, 0)
)

            db.commit()

            #reset session failed logins to prevent issues
            if 'failed_logins' in session:
                session['failed_logins'] = 0
            session['user_id'] = user_id
            return redirect(url_for('home',id_=user_id))
        except sqlite3.Error as e:
            print(f"Database error during user creation: {e}")
            flash("An error occurred. Please try again.", 'alert-danger')
            return render_template('user_creation.html')
        
        finally:
            db.close()
        
    return render_template("user_creation.html")

@app.route('/home', methods=['GET'])
def home_reroute():
    if session.get('user_id'):
        return redirect(url_for('home',id_=session.get('user_id')))
    else:
        return redirect(url_for('login'))

@app.route('/home/<string:id_>', methods=['GET'])
def home(id_):
    if id_ != session.get('user_id'):
        return redirect(url_for('login'))
    db = sqlite3.connect(config.CREDENTIALS_FILE)
    row = db.execute("SELECT username, permissions FROM users WHERE id == ?",(id_,)).fetchone()
    db.close()
    if row:
        username, perms = row
    
    permission_type = ''
    if perms <= 1:
        permission_type = 'admin'
    elif perms == 2:
        permission_type = 'eng'
    else:
        permission_type = 'user'
    session['role'] = permission_type
    
    return render_template('home.html',user=username,permissions=perms)

@app.route('/user/search', methods=['GET'])
def user_search():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    role = session.get('role')
    return render_template('search.html',type=role)

@app.route('/engineer/search', methods=['GET'])
def eng_search():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    role = session.get('role')
    #locks out users who access restricted info
    if role == 'user':
        db = sqlite3.connect(config.CREDENTIALS_FILE)
        db.execute("UPDATE users SET locked = 1 WHERE id == ?",(session['user_id'],))
        db.commit()
        db.close()
        return redirect(url_for('locked_out'))
    
    return render_template('search.html',type=role)

@app.route('/admin/search', methods=['GET'])
def adm_search():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    role = session.get('role')

    #locks out users who access restricted info
    if role == 'user' or role == 'eng':
        db = sqlite3.connect(config.CREDENTIALS_FILE)
        db.execute("UPDATE users SET locked = 1 WHERE id == ?",(session['user_id'],))
        db.commit()
        db.close()
        return redirect(url_for('locked_out'))
    
    return render_template('search.html',type=role)


if __name__ == "__main__":
    app.run(port=12345)