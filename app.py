from flask import (
    Flask, render_template, session, request, url_for, flash, redirect
)
import config
import sqlite3
import uuid
import hash
import re

app = Flask(__name__)

app.config.from_object('config')


@app.route('/', methods=['GET', 'POST'])
def start():
    """Initialise session counters and redirect to the login page."""
    if 'failed_logins' not in session:
        session['failed_logins'] = 0
    return redirect(url_for('login'), 302)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login.

    GET: render the login form.
    POST: validate credentials against the database.

    Failed attempts are tracked both in the session (per-browser) and in the
    database (per-account).  Either counter reaching MAX_ATTEMPTS triggers a
    lock.  A successful login resets both counters.
    """
    if session.get('failed_logins', 0) > config.MAX_ATTEMPTS:
        return redirect(url_for('locked_out'))

    if request.method == 'POST':
        username = request.form.get('username')
        attempted_password = request.form.get('password')

        db = None
        try:
            db = sqlite3.connect(config.CREDENTIALS_FILE)
            row = db.execute(
                "SELECT id, password, locked, failed_attempts "
                "FROM users WHERE username = ?;",
                (username,)
            ).fetchone()

            if row:
                user_id, recorded_password, locked, failed_attempts = row
            else:
                session['failed_logins'] += 1
                flash("Invalid username or password.")
                return render_template('login.html',
                                       title="Login Page",
                                       heading="Login Page")

            if locked:
                return redirect(url_for('locked_out'))

            if hash.authenticate(recorded_password, attempted_password):
                # Reset both session and database counters on success.
                session['failed_logins'] = 0
                db.execute(
                    "UPDATE users SET failed_attempts = 0 WHERE id == ?",
                    (user_id,)
                )
                db.commit()
                session['user_id'] = user_id
                return redirect(url_for('home', id_=user_id))
            else:
                if (
                    failed_attempts >= config.MAX_ATTEMPTS
                    or session.get('failed_logins') >= config.MAX_ATTEMPTS
                ):
                    db.execute(
                        "UPDATE users SET locked = 1 WHERE id == ?",
                        (user_id,)
                    )
                    db.commit()
                    return redirect(url_for('locked_out'))

                session['failed_logins'] += 1
                db.execute(
                    "UPDATE users SET failed_attempts = failed_attempts + 1 "
                    "WHERE id == ?",
                    (user_id,)
                )
                db.commit()
                flash("Invalid username or password.")

        except sqlite3.Error as e:
            print(f"Database error during login: {e}")
            flash("Invalid username or password.")

        finally:
            if db:
                db.close()

    return render_template('login.html',
                           title="Login Page",
                           heading="Login Page")


@app.route('/logout', methods=['GET'])
def logout():
    """Clear the session and redirect to the login page."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/locked_out', methods=['GET'])
def locked_out():
    """Render the account-locked screen."""
    return render_template('locked.html', title="Locked out")


def validate_password(password: str) -> list[str]:
    """
    Validate a password against the required security criteria.

    Args:
        password: The plaintext password string to validate.

    Returns:
        A list of error message strings.  An empty list means the password
        satisfies all requirements.
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


@app.route('/user_creation', methods=['GET', 'POST'])
def create_user():
    """
    Handle new-user registration.

    GET: render the account-creation form.
    POST: validate the submitted username and password, then insert a new
           user row with permission level config.PERM_USER (least privileged).
           Resets the session failed-login counter on success.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate username whitespace before hitting the database.
        if username != username.strip():
            flash("Username must not have leading or trailing spaces.",
                  'alert-danger')
            return render_template('user_creation.html')

        # Server-side password validation (mirrors the JS checks).
        errors = validate_password(password)
        for error in errors:
            flash(error, 'alert-danger')
        if errors:
            return render_template('user_creation.html')

        db = sqlite3.connect(config.CREDENTIALS_FILE)
        try:
            username_is_taken = any(
                db.execute(
                    "SELECT username FROM users WHERE username == ?",
                    (username,)
                )
            )
            if username_is_taken:
                flash("Username is already taken.", 'alert-danger')
                return render_template('user_creation.html')

            user_id = str(uuid.uuid4())
            hashed_password = hash.hash_pw(password)

            db.execute(
                "INSERT INTO users "
                "(id, username, password, permissions, locked, failed_attempts)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username, hashed_password,
                 config.PERM_USER, 0, 0)
            )
            db.commit()

            # Reset session counter to prevent carry-over lockout issues.
            session['failed_logins'] = 0
            session['user_id'] = user_id
            return redirect(url_for('home', id_=user_id))

        except sqlite3.Error as e:
            print(f"Database error during user creation: {e}")
            flash("An error occurred. Please try again.", 'alert-danger')
            return render_template('user_creation.html')

        finally:
            db.close()

    return render_template("user_creation.html")


@app.route('/home', methods=['GET'])
def home_reroute():
    """Redirect authenticated users to their home page; others to login."""
    if session.get('user_id'):
        return redirect(url_for('home', id_=session.get('user_id')))
    return redirect(url_for('login'))


@app.route('/home/<string:id_>', methods=['GET'])
def home(id_):
    """
    Render the home page for the authenticated user.

    Verifies that the URL ID matches the session ID to prevent IDOR.
    Sets the session role based on the permission level stored in the database.
    """
    if id_ != session.get('user_id'):
        return redirect(url_for('login'))

    db = sqlite3.connect(config.CREDENTIALS_FILE)
    row = db.execute(
        "SELECT username, permissions FROM users WHERE id == ?",
        (id_,)
    ).fetchone()
    db.close()

    if not row:
        session.clear()
        return redirect(url_for('login'))

    username, perms = row

    if perms <= config.PERM_ADMIN:
        permission_type = 'admin'
    elif perms == config.PERM_ENGINEER:
        permission_type = 'eng'
    else:
        permission_type = 'user'

    session['role'] = permission_type
    return render_template('home.html', user=username, permissions=perms)


@app.route('/user/search', methods=['GET'])
def user_search():
    """Render the user-level search page (accessible to all roles)."""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    role = session.get('role')
    return render_template('search.html', type=role)


@app.route('/engineer/search', methods=['GET'])
def eng_search():
    """
    Render the engineer-level search page.

    Locks and redirects any user-role account that reaches this route,
    as it indicates an attempt to access restricted functionality.
    """
    if not session.get('user_id'):
        return redirect(url_for('login'))

    role = session.get('role')
    if role == 'user':
        db = sqlite3.connect(config.CREDENTIALS_FILE)
        db.execute(
            "UPDATE users SET locked = 1 WHERE id == ?",
            (session['user_id'],)
        )
        db.commit()
        db.close()
        return redirect(url_for('locked_out'))

    return render_template('search.html', type=role)


@app.route('/admin/search', methods=['GET'])
def adm_search():
    """
    Render the admin-level search page.

    Locks and redirects any user- or engineer-role account that reaches this
    route, as it indicates an attempt to access restricted functionality.
    """
    if not session.get('user_id'):
        return redirect(url_for('login'))

    role = session.get('role')
    if role in ('user', 'eng'):
        db = sqlite3.connect(config.CREDENTIALS_FILE)
        db.execute(
            "UPDATE users SET locked = 1 WHERE id == ?",
            (session['user_id'],)
        )
        db.commit()
        db.close()
        return redirect(url_for('locked_out'))

    return render_template('search.html', type=role)


if __name__ == "__main__":
    app.run(port=12345)
