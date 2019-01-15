from flask import Flask, render_template, request, Request, redirect,jsonify, url_for, flash, abort, session as login_session
app = Flask(__name__)

import random, string, json, httplib2, requests
from apiclient import discovery
from oauth2client import client
from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from passlib.context import CryptContext


#Connect to Database and create database session
engine = create_engine('sqlite:///catalogitemswithusers.db?check_same_thread=False')
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
    ## pbkdf2_sha256__rounds = 29000,
    )

def createUser(login_session):

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
    session = DBSession()
    user = session.query(User).filter_by(id = user_id).one()
    return user

def getUserIDbyEmail(user_email):
    try:
        session = DBSession()
        user = session.query(User).filter_by(email = user_email, auto_signin=False).one()
        return user.id
    except:
        return None

def getUserIDbyUsername(user_name):
    try:
        session = DBSession()
        user = session.query(User).filter_by(username = user_name, auto_signin=False).one()
        return user.id
    except:
        return None

@app.route('/catalog/JSON')
def CategoriesJSON():
    session = DBSession()
    categories = session.query(Category).all()
    return jsonify(categories= [c.serialize for c in categories])

@app.route('/catalog/<string:category_name>/items/JSON')
def ItemsJSON(category_name):
    session = DBSession()
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id)
    return jsonify(items= [i.serialize for i in items])

@app.route('/users/JSON')
def UsersJSON():
    session = DBSession()
    users = session.query(User).all()
    return jsonify(users= [u.serialize for u in users])

@app.route('/')
@app.route('/catalog')
def showCatalogs():
	session = DBSession()
	categories = session.query(Category).all()
	items = session.query(Item).order_by(desc(Item.id)).limit(9)
	return render_template('catalogs.html', categories=categories, items=items,
	 login_session=login_session)

@app.route('/catalog/<string:category_name>/items')
def showItems(category_name):
    session = DBSession()
    category = session.query(Category).filter_by(name=category_name).one_or_none()
    if category is None:
        return redirect(url_for('showCatalogs'))
    categories = session.query(Category).all()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return render_template('catalogs.html', category_name=category_name, category=category,
    	categories=categories, items=items, login_session=login_session)

@app.route('/catalog/<string:category_name>/items/<int:item_id>')
def showItemDetails(category_name, item_id):
    session = DBSession()
    # category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('itemDetails.html', item=item, login_session=login_session)

@app.route('/catalog/<string:category_name>/items/new', methods=['GET', 'POST'])
def newItem(category_name):
     session = DBSession()
     if request.method == 'POST':
          if not (request.args['state'] == login_session['state']):
              abort(403)
          user = session.query(User).filter_by(name=login_session['username']).one()
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
          return redirect(url_for('showItems', category_name=category_name, STATE=login_session['state']))
     else:
         return render_template('newItem.html', login_session=login_session)

@app.route('/catalog/<string:category_name>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(category_name, item_id):
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
              abort(403)
        user = session.query(User).filter_by(name=login_session['username']).one()
        category = session.query(Category).filter_by(name=category_name).one()

        item.name = request.form['name']
        item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('%s Successfully Edited' % item.name)
        return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('editItem.html', login_session=login_session, item=item)

@app.route('/catalog/<string:category_name>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(category_name, item_id):

    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
              abort(403)
        session.delete(item)
        session.commit()
        flash('%s Successfully Deleted' % item.name)
        return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('deleteItem.html', login_session=login_session, item=item)

@app.route('/catalog/<string:category_name>/items/delete', methods=['GET', 'POST'])
def deleteCategory(category_name):

    session = DBSession()
    category = session.query(Category).filter_by(name=category_name).one()
    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
              abort(403)
        session.delete(category)
        session.commit()
        flash('%s Successfully Deleted' % category.name)
        return redirect(url_for('showItems', login_session=login_session, category_name=category_name))
    else:
        return render_template('deleteCategory.html', login_session=login_session, category=category)

@app.route('/catalog/new', methods=['GET', 'POST'])
def newCategory():

    session = DBSession()
    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
              abort(403)
        user = session.query(User).filter_by(name=login_session['username']).one()
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
    # return "your session token is: " + login_session['state']
    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
            abort(403)
        email = request.form['inputEmail']
        password = request.form['inputPassword']
        EmailFound = getUserIDbyEmail(email)
        user = session.query(User).filter_by(id=EmailFound).one_or_none()
        userPassword = user.password if user else None

        passwordCorrect = pwd_context.verify(password, userPassword)

        if EmailFound and passwordCorrect:
            
            login_session['username'] = user.name
            login_session['picture'] = user.picture
            login_session['email'] = user.email

            flash("you are now logged in as %s" % login_session['username'])
            return redirect(url_for('showCatalogs'))    

        else:
            server_message = "sign in credentials are not correct."

            return render_template('login.html', STATE=login_session['state'], server_message=server_message)
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
        login_session['state'] = state

        return render_template('login.html', STATE=state)

@app.route('/signup', methods=['GET', 'POST'])
def showSignup():

    if request.method == 'POST':
        if not (request.args['state'] == login_session['state']):
            abort(403)

        new_user = {}
        new_user['username'] = request.form['inputUsername']
        new_user['password'] = request.form['inputPassword']
        new_user['email'] = request.form['inputEmail']
        new_user['picture'] = None
        new_user['auto_signin'] = False
        EmailFound = getUserIDbyEmail(new_user['email'])
        UsernameFound = getUserIDbyUsername(new_user['username'])
        if EmailFound:
            server_message = "email address already exists."
            del new_user
            return render_template('signup.html', STATE=login_session['state'], 
                server_message=server_message)
        elif UsernameFound:
            server_message = "username already exists. Please choose another one."
            del new_user
            return render_template('signup.html', STATE=login_session['state'], 
                server_message=server_message)
        else:
            createUser(new_user)
            flash('You\'ve created your account Successfully. now use your credentials to sign in.')
            return redirect(url_for('showCatalogs'))    
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
        login_session['state'] = state
        return render_template('signup.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():

	# if state token not identical with the one in login_session, this could be a CSRF
    if not (request.args['state'] == login_session['state']):
        abort(403)
    # (Receive auth_code by HTTPS POST)

    # auth_code = json.loads(Request.get_json(request.data))
    print(request.get_data(as_text=True))
    auth_code = request.get_data(as_text=True)
    # If this request does not have `X-Requested-With` header, this could be a CSRF
    if not request.headers.get('X-Requested-With'):
        abort(403)

    # Set path to the Web application client_secret_*.json file you downloaded from the
    # Google API Console: https://console.developers.google.com/apis/credentials
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
    drive_service = discovery.build('drive', 'v3', http=http_auth)
    appfolder = drive_service.files().list()

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

    session = DBSession()

    login_session['user_id'] = getUserIDbyEmail(login_session['email'])

    print("login_session['user_id'] = " + str(login_session['user_id']))

    if login_session['user_id'] is None:
        login_session['user_id'] = createUser(login_session)

    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state


    output = ''
    output += login_session['username'] + "is logged in."
    flash("you are now logged in as %s" % login_session['username'])
    print(output)
    print ("done!")
    return ('', 204)

@app.route('/signout')
def signout():

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
  app.run(host = '0.0.0.0', port = 8000)