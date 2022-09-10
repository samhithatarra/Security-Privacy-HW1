from app.models.breaches import get_breaches
import hashlib
from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user, SALT
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)


@get('/login')
def login():
    return template('login')

@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    hashed_salted_password = hashlib.pbkdf2_hmac('sha256', request.forms.get('password').encode('utf-8'), bytes.fromhex(SALT), 100000).hex()

    error = None
    user = get_user(db, username)
    print(user)
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        
        elif user.password != hashed_salted_password:
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login


    elif (request.forms.get("register")):
        if user is not None:
            response.status = 401
            error = "{} is already taken.".format(username)

        elif get_breaches(db, username, password) != ([], [], []):
            print(get_breaches(db, username, password))
            response.status = 401
            error = "Username password combination found in breaches."

        else:
            create_user(db, username, password)
                
    else:
        response.status = 400
        error = "Submission error."

    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
        
    return template("login", error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")


