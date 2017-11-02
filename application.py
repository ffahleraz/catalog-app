#!/usr/bin/env python3

import os
import random
import string
import httplib2
import json
import requests

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from flask import session as login_session
from flask import make_response
from flask import (Flask, render_template, request, redirect, jsonify,
url_for, flash)

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from database_setup import Base, User, Category, Item

app = Flask(__name__)

# Client ID for Google OAuth2
CLIENT_ID = json.loads(
    open('gconnect_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "BRAG"

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
db_session = DBSession()


@app.route('/login/')
def showLogin():
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('gconnect_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    str_response = h.request(url, 'GET')[1].decode('utf-8')
    result = json.loads(str_response)
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
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

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


@app.route('/logout/')
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print ('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    print ('In gdisconnect access token is %s', access_token)
    print ('User name is: ')
    print (login_session['username'])

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    print ('result is ')
    print (result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    db_session.add(newUser)
    db_session.commit()
    user = db_session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = db_session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = db_session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/')
def showHome():
    categories = db_session.query(Category).all()
    featured_items = (
        db_session.query(Item).order_by(Item.time_added)
        .limit(10).all())
    if 'username' in login_session:
        user = (
            db_session.query(User)
            .filter_by(id=login_session['user_id']).first())
        return render_template('home_in.html', categories=categories,
                               featured_items=featured_items, user=user)
    else:
        return render_template('home_out.html', categories=categories,
                               featured_items=featured_items)


@app.route('/category/<string:category_name>/')
def showCategory(category_name):
    categories = db_session.query(Category).all()
    category = db_session.query(Category).filter_by(name=category_name).first()
    if not category:
        return "Category not found."
    items = db_session.query(Item).filter_by(category_id=category.id).all()
    if 'username' in login_session:
        user = (
            db_session.query(User)
            .filter_by(id=login_session['user_id']).first())
        return render_template('category_in.html', items=items,
                               current_category=category,
                               categories=categories, user=user)
    else:
        return render_template('category_out.html', items=items,
                               current_category=category,
                               categories=categories)


@app.route('/owner/<int:user_id>/')
def showUserItems(user_id):
    categories = db_session.query(Category).all()
    if 'username' in login_session and user_id == login_session['user_id']:
        user = (
            db_session.query(User)
            .filter_by(id=login_session['user_id']).first())
        items = db_session.query(Item).filter_by(user_id=user.id).all()
        return render_template('owner_in.html', items=items,
                               categories=categories, user=user)
    else:
        return "You are not logged in as this user."


@app.route('/new/', methods=['GET', 'POST'])
def newItem():
    categories = db_session.query(Category).all()
    if 'username' in login_session:
        user = (
            db_session.query(User)
            .filter_by(id=login_session['user_id']).first())
        if request.method == 'GET':
            return render_template('new_item.html', categories=categories,
                                   user=user)
        else:
            category = db_session.query(Category).filter_by(
                name=request.form['category']).first()
            newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           price=int(request.form['price']),
                           year=int(request.form['year']),
                           time_added=datetime.now(),
                           category_id=category.id,
                           user_id=user.id)
            db_session.add(newItem)
            db_session.commit()
            flash("Item '{}' added!".format(newItem.name))
            return redirect(url_for('showUserItems', user_id=user.id))
    else:
        return "You must be logged in to add new items."


@app.route('/item/<int:item_id>/edit/', methods=['GET', 'POST'])
def editItem(item_id):
    categories = db_session.query(Category).all()
    item = db_session.query(Item).filter_by(id=item_id).first()
    if not item:
        return "Item not found."
    user = db_session.query(User).filter_by(id=item.user_id).first()
    if 'username' in login_session and item.user_id == login_session['user_id']:
        if request.method == 'GET':
            return render_template('edit_item.html', item=item,
                                   categories=categories, user=user)
        else:
            category = db_session.query(Category).filter_by(
                name=request.form['category']).first()
            item.name = request.form['name']
            item.description = request.form['description']
            item.price = int(request.form['price'])
            item.year = int(request.form['year'])
            item.category_id = category.id
            flash("Changes to '{}' saved!".format(item.name))
            db_session.add(item)
            db_session.commit()
            return redirect(url_for('showUserItems', user_id=user.id))
    else:
        return "You are not authorized to edit this item."


@app.route('/item/<int:item_id>/delete/', methods=['GET', 'POST'])
def deleteItem(item_id):
    categories = db_session.query(Category).all()
    item = db_session.query(Item).filter_by(id=item_id).first()
    if not item:
        return "Item not found."
    user = db_session.query(User).filter_by(id=item.user_id).first()
    if 'username' in login_session and item.user_id == login_session['user_id']:
        if request.method == 'GET':
            return render_template('delete_item.html', item=item,
                                   categories=categories, user=user)
        else:
            flash("Item '{}' deleted!".format(item.name))
            db_session.delete(item)
            db_session.commit()
            return redirect(url_for('showUserItems', user_id=user.id))
    else:
        return "You are not authorized to delete this item."


@app.route('/item/<int:item_id>/')
def showItem(item_id):
    categories = db_session.query(Category).all()
    item = db_session.query(Item).filter_by(id=item_id).first()
    if not item:
        return "Item not found."
    if 'username' in login_session:
        user = (
            db_session.query(User)
            .filter_by(id=login_session['user_id']).first())
        if item.user_id == login_session['user_id']:
            return render_template('item.html', categories=categories,
                                   item=item, user=user, logged_in=True, owned=True)
        else:
            return render_template('item.html', categories=categories,
                                   item=item, user=user, logged_in=True, owned=False)
    else:
        return render_template('item.html', categories=categories,
                               item=item, user=None, logged_in=False, owned=False)


@app.route('/api/categories/')
def returnCategoriesJSON():
    categories = db_session.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])

@app.route('/api/category/<string:category_name>/')
def returnCategoryJSON(category_name):
    category = db_session.query(Category).filter_by(name=category_name).first()
    if not category:
        return "Category not found."
    items = db_session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(Items=[i.serialize for i in items])


if __name__ == '__main__':
    app.secret_key = 'secret_key'
    app.debug = True

    # for vagrant
    #port = int(os.environ.get('PORT', 8000))
    #app.run(host='0.0.0.0', port=port)

    # set these according to your deployment
    port = int(os.environ.get('PORT', 80))
    app.run(host='83.136.252.85', port=port)
