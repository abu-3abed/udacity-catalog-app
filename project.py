from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash, abort, session as login_session

import random
import string
import httplib2
import requests
from apiclient import discovery
from oauth2client import client
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from passlib.context import CryptContext

app = Flask(__name__)

# Connect to Database and create database session
engine = create_engine(
    'sqlite:///catalogitemswithusers.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#
# create a single global instance for your app...
#
pwd_context = CryptContext(
    # Replace this list with the hash(es) you wish to support.
    # this example sets pbkdf2_sha256 as the default,
    # with additional support for reading legacy des_crypt hashes.
    schemes=["pbkdf2_sha256", "des_crypt"],

    # Automatically mark all but first hasher in list as deprecated.
    # (this will be the default in Passlib 2.0)
    deprecated="auto",

    # Optionally, set the number of rounds that should be used.
    # Appropriate values may vary for different schemes,
    # and the amount of time you wish it to take.
    # Leaving this alone is usually safe, and will use passlib's defaults.

    # pbkdf2_sha256__rounds = 29000,
)


def createUser(login_session):
    """ createUser(login_session): this function will take Flask's session
        object filled with user's credentials and will create new user in table
        'user' and return back his new id.
        """

    if login_session['auto_signin']:
        newUser = User(name=login_session['username'],
                       email=login_session['email'],
                       picture=login_session['picture'],
                       auto_signin=True)
    else:
        newUser = User(name=login_session['username'],
                       password=pwd_context.hash(login_session['password']),
                       email=login_session['email'],
                       picture=login_session['picture'],
                       auto_signin=False)
    session = DBSession()
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ this function searches for user by id and returns it."""
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserIDbyEmail(user_email):
    """ this function searches for user by email and then returns his
     id; otherwise None."""

    session = DBSession()
    user = session.query(User).filter_by(
        email=user_email, auto_signin=False).one_or_none()
    if user:
        return user.id
    else:
        return None


def getUserIDbyUsername(user_name):
    """ this function searches for user by username and then returns his
    id; otherwise None."""
    session = DBSession()
    user = session.query(User).filter_by(
        name=user_name, auto_signin=False).one_or_none()
    if user:
        return user.id
    else:
        return None


@app.route('/catalog/JSON')
def CategoriesJSON():
    """ This is a JSON endpoint which returns list of available categories."""
    session = DBSession()
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/catalog/<string:category_name>/items/JSON')
def ItemsJSON(category_name):
    """ This is a JSON endpoint which returns available items per category."""
    session = DBSession()
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id)
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<string:category_name>/items/<int:item_id>/JSON')
def SingleItemJSON(category_name, item_id):
    """ This is a JSON endpoint which returns a specific item per category."""
    session = DBSession()
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(category_id=category.id, id=item_id)
    return jsonify(item=item.serialize)


@app.route('/users/JSON')
def UsersJSON():
    """ This is a JSON endpoint which returns list of all registered users."""
    session = DBSession()
    users = session.query(User).all()
    return jsonify(users=[u.serialize for u in users])


@app.route('/')
@app.route('/catalog')
def showCatalogs():
    """ This endpoint is the home screen where it shows available categories"""
    session = DBSession()
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(9)
    return render_template('catalogs.html', categories=categories, items=items,
                           login_session=login_session)


@app.route('/catalog/<string:category_name>/items')
def showItems(category_name):
    """ This endpoint is the same home screen except it shows content
     of one of the categories."""
    session = DBSession()
    category = session.query(Category).filter_by(name=category_name).one()
    categories = session.query(Category).all()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return render_template(
        'catalogs.html',
        category_name=category_name,
        category=category,
        categories=categories,
        items=items,
        login_session=login_session
    )


@app.route('/catalog/<string:category_name>/items/<int:item_id>')
def showItemDetails(category_name, item_id):
    """ This endpoint shows item details (name, description, etc)
     and it shows Edit and Delete buttons for authors. """
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('itemDetails.html',
                           item=item,
                           login_session=login_session)


@app.route('/catalog/<string:category_name>/items/new',
           methods=['GET', 'POST'])
def newItem(category_name):
    """ This endpoint will show new item form by GET request and will
     add the new item by POST request."""
    session = DBSession()
    if request.method == 'POST' and login_session['username']:
        # CSRF fix
        if not (request.args['state'] == login_session['state']):
            abort(403)
        # querying current user info to add it to new item object.
        user = session.query(User).filter_by(
            name=login_session['username']).one()
        category = session.query(Category).filter_by(name=category_name).one()
        item = Item(name=request.form['name'],
                    description=request.form['description'],
                    category=category,
                    category_id=category.id,
                    user=user,
                    user_id=user.id)
        session.add(item)
        session.commit()
        flash('%s Successfully Created' % item.name)
        return redirect(url_for('showItems',
                                category_name=category_name,
                                STATE=login_session['state']))
    else:
        return render_template('newItem.html', login_session=login_session)


@app.route('/catalog/<string:category_name>/items/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(category_name, item_id):
    """ This endpoint will show edit item form by GET request and will overwrite
     the edited item by POST request."""
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST' and login_session['username']:
        # CSRF fix
        if not (request.args['state'] == login_session['state']):
            abort(403)

        item.name = request.form['name']
        item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('%s Successfully Edited' % item.name)
        return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('editItem.html',
                               login_session=login_session,
                               item=item)


@app.route('/catalog/<string:category_name>/items/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_name, item_id):
    """ This endpoint will show item delete confirmation by GET request and
     will delete the item by POST request."""
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST' and login_session['username']:
        # CSRF fix
        if not (request.args['state'] == login_session['state']):
            abort(403)
        session.delete(item)
        session.commit()
        flash('%s Successfully Deleted' % item.name)
        return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('deleteItem.html',
                               login_session=login_session,
                               item=item)


@app.route('/catalog/<string:category_name>/items/delete',
           methods=['GET', 'POST'])
def deleteCategory(category_name):
    """ This endpoint will show category delete confirmation by GET request
     and will delet the category by POST request."""
    session = DBSession()
    category = session.query(Category).filter_by(name=category_name).one()
    if request.method == 'POST' and login_session['username']:
        # CSRF fix
        if not (request.args['state'] == login_session['state']):
            abort(403)
        session.delete(category)
        session.commit()
        flash('%s Successfully Deleted' % category.name)
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('deleteCategory.html',
                               login_session=login_session,
                               category=category)


@app.route('/catalog/new', methods=['GET', 'POST'])
def newCategory():
    """ This endpoint will show new category form by GET request and will add
     the new category by POST request."""
    session = DBSession()
    if request.method == 'POST' and login_session['username']:
        if not (request.args['state'] == login_session['state']):
            abort(403)
        # querying current user info to add it to new item object.
        user = session.query(User).filter_by(
            name=login_session['username']).one()
        category = Category(name=request.form['title'],
                            user=user,
                            user_id=user.id)
        session.add(category)
        session.commit()
        flash('%s Successfully Created' % category.name)
        return redirect(url_for('showItems', category_name=category.name))
    else:
        return render_template('newCategory.html', login_session=login_session)


@app.route('/login', methods=['GET', 'POST'])
def showLogin():
    """ This endpoint will show login form by GET request and will take user
     credentials and log him in by POST request."""
    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
            abort(403)

        email = request.form['inputEmail']
        password = request.form['inputPassword']
        # EmailFound = user id or None if not found.
        EmailFound = getUserIDbyEmail(email)
        user = session.query(User).filter_by(id=EmailFound).one_or_none()
        userPassword = user.password if user else None
        # check if entered password equals its counterpart hashed password.
        # returns True if they equal, false otherwise.
        passwordCorrect = pwd_context.verify(password, userPassword)

        if EmailFound and passwordCorrect:

            login_session['username'] = user.name
            login_session['picture'] = user.picture
            login_session['email'] = user.email

            flash("you are now logged in as %s" % login_session['username'])
            return redirect(url_for('showCatalogs'))

        else:  # if EmailFound = None AND passwordCorrect = False
            server_message = "sign in credentials are not correct."

            return render_template('login.html',
                                   STATE=login_session['state'],
                                   server_message=server_message)
    else:
        # generate a new state token for user sign in process and store
        # it in Flask session store.
        state = ''.join(random.choice(string.ascii_uppercase +
                                      string.digits) for x in range(32))
        login_session['state'] = state

        return render_template('login.html', STATE=state)


@app.route('/signup', methods=['GET', 'POST'])
def showSignup():
    """ This endpoint will show signup form by GET request and will take user
     credentials and sign him up by POST request."""
    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
            abort(403)

        new_user = {}
        new_user['username'] = request.form['inputUsername']
        new_user['password'] = request.form['inputPassword']
        new_user['email'] = request.form['inputEmail']
        new_user['picture'] = None
        # new_user['auto_signin'] = True if auto-signin maechanism used
        # (ex: Google, Facebook) otherwise False.
        new_user['auto_signin'] = False
        # EmailFound = user id or None if not found.
        EmailFound = getUserIDbyEmail(new_user['email'])
        # UsernameFound = user id or None if not found.
        UsernameFound = getUserIDbyUsername(new_user['username'])

        # user credentials check mechanism.
        if EmailFound:
            server_message = "email address already exists."
            del new_user
            return render_template('signup.html', STATE=login_session['state'],
                                   server_message=server_message)
        elif UsernameFound:
            server_message = """username already exists.
                                Please choose another one."""
            del new_user
            return render_template('signup.html', STATE=login_session['state'],
                                   server_message=server_message)
        else:  # if email not found and username not found.
            createUser(new_user)
            flash(
                """You\'ve created your account Successfully.
                 now use your credentials to sign in.""")
            return redirect(url_for('showCatalogs'))
    else:
        # generate a new state token for user sign up process and store
        # it in Flask session store.
        state = ''.join(random.choice(string.ascii_uppercase +
                                      string.digits) for x in range(32))
        login_session['state'] = state
        return render_template('signup.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ This endpoint is a POST-only endpoint which log users in by their
     google accounts from within signin and signup page."""

    # if state token not identical with the one in login_session,
    # this could be a CSRF
    if not (request.args['state'] == login_session['state']):
        abort(403)
    # (Receive auth_code by HTTPS POST)

    # auth_code = json.loads(Request.get_json(request.data))
    print(request.get_data(as_text=True))
    auth_code = request.get_data(as_text=True)
    # If this request does not have `X-Requested-With` header,
    # this could be a CSRF
    if not request.headers.get('X-Requested-With'):
        abort(403)

    # Set path to the Web application client_secret_*.json file you
    # downloaded from the Google API Console:
    # https://console.developers.google.com/apis/credentials
    CLIENT_SECRET_FILE = 'client_secrets.json'

    # Exchange auth code for access token, refresh token, and ID token
    credentials = client.credentials_from_clientsecrets_and_code(
        CLIENT_SECRET_FILE,
        ['https://www.googleapis.com/auth/drive.appdata', 'profile', 'email'],
        auth_code)
    print(credentials)

    # Call Google API
    http_auth = credentials.authorize(httplib2.Http())
    print(http_auth)

    # Get profile info from ID token
    gplus_id = credentials.id_token['sub']
    email = credentials.id_token['email']
    print(gplus_id)
    print(email)

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['auto_signin'] = True

    login_session['user_id'] = getUserIDbyEmail(login_session['email'])

    print("login_session['user_id'] = " + str(login_session['user_id']))

    if login_session['user_id'] is None:
        login_session['user_id'] = createUser(login_session)

    # generate a new state token after user signing up and
    # store it in Flask session store.
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state

    output = ''
    output += login_session['username'] + "is logged in."
    flash("you are now logged in as %s" % login_session['username'])
    print(output)
    print("done!")
    return ('', 204)


@app.route('/signout')
def signout():
    """ This GET-only endpoint will sign users out."""
    login_session.pop('username', None)
    login_session.pop('picture', None)
    login_session.pop('email', None)
    login_session.pop('user_id', None)
    login_session.pop('state', None)

    flash('You\'re signed out.')
    return redirect(url_for('showCatalogs'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
