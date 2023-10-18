from flask import Flask, request, jsonify, Response
import jwt
import datetime
from pymongo import MongoClient
from bson import json_util
from flask_cors import CORS
import re

application = Flask(__name__)
CORS(application)
application.config['SECRET_KEY'] = 'gcsecretkey'
client = MongoClient('mongodb+srv://tsbgalcontract:mymongodb26@cluster0.kppkt.mongodb.net/test?authSource=admin&replicaSet=atlas-8jvx35-shard-0&readPreference=primary&appname=MongoDB%20Compass&ssl=true')
db = client['galcontract_crm']
users_collection = db['users']
clients_collection = db['clients']
protocols_collection = db['protocols']


@application.route('/', methods=['GET'])
def test():
    return 'GalcontractCRM API v1.0'


SECRET_KEY = 'gcsecretkey'


# Sample function to verify access token
def verify_access_token(access_token):
    try:
        decoded_token = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
        # If the token is successfully decoded, it is valid
        return True
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Invalid token
        return False


# Sample function to verify refresh token
def verify_refresh_token(refresh_token):
    try:
        decoded_token = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
        # If the token is successfully decoded, it is valid
        return True
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Invalid token
        return False


@application.route('/validate_tokens', methods=['POST'])
def validate_tokens():
    data = request.get_json()
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')

    if not access_token and not refresh_token:
        response = jsonify({'message': 'Access token or refresh token is missing'}), 401
        return response

    access_token_valid = verify_access_token(access_token) if access_token else False
    refresh_token_valid = verify_refresh_token(refresh_token) if refresh_token else False

    if access_token_valid:
        response = jsonify({'message': 'Access token is valid', 'valid': True}), 200
    elif refresh_token_valid:
        response = jsonify({'message': 'Refresh token is valid', 'valid': True}), 200
    else:
        response = jsonify({'message': 'Access token or refresh token is invalid', 'valid': False}), 401

    return response


# Endpoint for user login
@application.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the user exists in the database and the password matches
    user = users_collection.find_one({'username': username, 'password': password})

    if user:
        # Generate tokens
        access_token = jwt.encode(
            {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            application.config['SECRET_KEY'], algorithm='HS256')
        refresh_token = jwt.encode(
            {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)},
            application.config['SECRET_KEY'], algorithm='HS256')

        response = jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
        return response
    else:
        response = jsonify({'message': 'Invalid credentials'}), 401
        return response


# Endpoint for token refresh
@application.route('/refresh', methods=['POST'])
def refresh():
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    try:
        # Decode the refresh token
        decoded_token = jwt.decode(refresh_token, application.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token['username']

        # Generate a new access token
        access_token = jwt.encode(
            {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            application.config['SECRET_KEY'], algorithm='HS256')

        response = jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
        return response
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


# Endpoint for clients module
@application.route('/clients', methods=['POST'])
def clients():
    data = request.get_json()
    access_token = data.get('access_token')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    # Extract filter parameters from the request data
    keyword = data.get('keyword')
    code = data.get('code')
    name = data.get('name')
    telephone = data.get('telephone')
    email = data.get('email')
    register_date_start = data.get('register_date_start')
    register_date_end = data.get('register_date_end')
    create_date_start = data.get('create_date_start')
    create_date_end = data.get('create_date_end')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        decoded_token = jwt.decode(access_token, application.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token['username']
        # Add your logic to retrieve user information based on the username from the database
        # For example, user_info = get_user_info(username)

        # Construct the filter criteria for the MongoDB query
        filter_criteria = {}
        if keyword:
            clients_collection.create_index([("$**", "text")])
            filter_criteria['$text'] = {'$search': keyword}
        if code:
            regex_pattern = f'.*{re.escape(code)}.*'
            filter_criteria['code'] = {'$regex': regex_pattern, '$options': 'i'}
        if name:
            clients_collection.create_index([("$**", "text")])
            filter_criteria['$text'] = {'$search': name}
        if telephone:
            regex_pattern = f'.*{re.escape(telephone)}.*'
            filter_criteria['telephone'] = {'$regex': regex_pattern, '$options': 'i'}
        if email:
            regex_pattern = f'.*{re.escape(email)}.*'
            filter_criteria['login'] = {'$regex': regex_pattern, '$options': 'i'}
        if register_date_start or register_date_end:
            try:
                start_date = datetime.datetime.strptime(register_date_start, '%d-%m-%Y')
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(register_date_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['register_date'] = {"$gte": start_date, "$lte": end_date}
        if create_date_start or create_date_end:
            try:
                start_date = datetime.datetime.strptime(create_date_start, '%d-%m-%Y')
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(create_date_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['create_date'] = {"$gte": start_date, "$lte": end_date}

        # Count the total number of clients that match the filter criteria
        total_clients = clients_collection.count_documents(filter_criteria)

        # Paginate the query results using skip and limit, and apply filters
        skip = (page - 1) * per_page
        documents = list(clients_collection.find(filter_criteria).skip(skip).limit(per_page))

        # Calculate the range of clients being displayed
        start_range = skip + 1
        end_range = min(skip + per_page, total_clients)

        # Serialize the documents using json_util from pymongo and specify encoding
        response = Response(json_util.dumps({'clients': documents, 'total_clients': total_clients, 'start_range': start_range, 'end_range': end_range}, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json;charset=utf-8')
        return response, 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/add_comment', methods=['POST'])
def add_comment():
    data = request.get_json()
    access_token = data.get('access_token')
    user_id = data.get('id')
    comment = data.get('comment')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        if not user_id or not comment:
            response = jsonify({'message': 'User ID or comment is missing'}), 400
            return response

        # Search for the user document by ID and update the 'comment' field
        result = clients_collection.update_one({'id': user_id}, {'$set': {'comment': comment}})

        if result.modified_count == 1:
            response = jsonify({'message': 'Comment added successfully'}), 200
        else:
            response = jsonify({'message': 'User not found or comment not added'}), 404

        return response
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/protocols', methods=['POST'])
def protocols():
    data = request.get_json()
    access_token = data.get('access_token')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    # Extract filter parameters from the request data
    keyword = data.get('keyword')
    code = data.get('code')
    name = data.get('name')
    telephone = data.get('telephone')
    email = data.get('email')
    register_date_start = data.get('register_date_start')
    register_date_end = data.get('register_date_end')
    create_date_start = data.get('create_date_start')
    create_date_end = data.get('create_date_end')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        decoded_token = jwt.decode(access_token, application.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token['username']
        # Add your logic to retrieve user information based on the username from the database
        # For example, user_info = get_user_info(username)

        # Construct the filter criteria for the MongoDB query
        filter_criteria = {}
        if keyword:
            protocols_collection.create_index([("$**", "text")])
            filter_criteria['$text'] = {'$search': keyword}
        if code:
            regex_pattern = f'.*{re.escape(code)}.*'
            filter_criteria['code'] = {'$regex': regex_pattern, '$options': 'i'}
        if name:
            protocols_collection.create_index([("$**", "text")])
            filter_criteria['$text'] = {'$search': name}
        if telephone:
            regex_pattern = f'.*{re.escape(telephone)}.*'
            filter_criteria['telephone'] = {'$regex': regex_pattern, '$options': 'i'}
        if email:
            regex_pattern = f'.*{re.escape(email)}.*'
            filter_criteria['login'] = {'$regex': regex_pattern, '$options': 'i'}
        if register_date_start or register_date_end:
            try:
                start_date = datetime.datetime.strptime(register_date_start, '%d-%m-%Y')
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(register_date_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['register_date'] = {"$gte": start_date, "$lte": end_date}
        if create_date_start or create_date_end:
            try:
                start_date = datetime.datetime.strptime(create_date_start, '%d-%m-%Y')
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(create_date_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['create_date'] = {"$gte": start_date, "$lte": end_date}

        # Count the total number of clients that match the filter criteria
        total_clients = protocols_collection.count_documents(filter_criteria)

        # Paginate the query results using skip and limit, and apply filters
        skip = (page - 1) * per_page
        documents = list(protocols_collection.find(filter_criteria).skip(skip).limit(per_page))

        # Calculate the range of clients being displayed
        start_range = skip + 1
        end_range = min(skip + per_page, total_clients)

        # Serialize the documents using json_util from pymongo and specify encoding
        response = Response(json_util.dumps({'protocols': documents, 'total_clients': total_clients, 'start_range': start_range, 'end_range': end_range}, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json;charset=utf-8')
        return response, 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


if __name__ == '__main__':
    application.run()
