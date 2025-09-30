from flask import Flask, request, jsonify, Response
import jwt
import datetime
from pymongo import MongoClient, DESCENDING
from bson import json_util, ObjectId
from flask_cors import CORS
import re
from flask_mail import Mail, Message
import requests
from bs4 import BeautifulSoup as bs


ALLOWED_ORIGINS = {
    "https://galcontract-crm-front-ce5m4.ondigitalocean.app",
}

CORS(
    application,
    resources={r"/*": {
        "origins": list(ALLOWED_ORIGINS),
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "supports_credentials": True,
        "max_age": 86400,
    }},
)

application = Flask(__name__)
application.config['SECRET_KEY'] = 'gcsecretkey'
client = MongoClient('mongodb+srv://tsbgalcontract:mymongodb26@cluster0.kppkt.mongodb.net/test?authSource=admin&replicaSet=atlas-8jvx35-shard-0&readPreference=primary&appname=MongoDB%20Compass&ssl=true')
db = client['galcontract_crm']
users_collection = db['users']
clients_collection = db['clients']
protocols_collection = db['protocols_test']
protocols_all_collection = db['protocols_all']
biprozorro_collection = db['biprozorro']
biprozorro_test_collection = db['biprozorro_test']
mailing_search_collection = db['mailing_search']
streams_collection = db['streams']
procuringEntity_auctions_collection = db['procuringEntity_auctions']
comments_collection = db['comments']

application.config['MAIL_SERVER']='smtp.gmail.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_USERNAME'] = 'bagriul@gmail.com'
application.config['MAIL_PASSWORD'] = 'hxih utim ntwh ppuv'
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
mail = Mail(application)


@application.after_request
def add_cors_headers(resp):
    # завжди додати CORS для дозволених оріджинів, навіть на 4xx/5xx
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    return resp


# миттєва відповідь на preflight
@application.route("/__preflight__", methods=["OPTIONS"])
def preflight_probe():
    return ("", 204)


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
    page = data.get('page', 1)
    per_page = data.get('per_page', 10)

    # Extract filter parameters from the request data
    keyword = data.get('keyword')
    comment = data.get('comment')
    code = data.get('code')
    name = data.get('name')
    telephone = data.get('telephone')
    email = data.get('email')
    register_date_start = data.get('register_date_start')
    register_date_end = data.get('register_date_end')
    create_date_start = data.get('create_date_start')
    create_date_end = data.get('create_date_end')
    stream = data.get('stream')  # New stream filter

    if not access_token:
        return jsonify({'message': 'Access token is missing'}), 401

    try:
        decoded_token = jwt.decode(access_token, application.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token['username']
        # Retrieve user information based on the username, if needed

        # Construct the filter criteria for the MongoDB query
        filter_criteria = {}
        if keyword:
            clients_collection.create_index([("$**", "text")])
            filter_criteria['$text'] = {'$search': keyword}
        if comment:
            regex_pattern = f'.*{re.escape(comment)}.*'
            filter_criteria['comment'] = {'$regex': regex_pattern, '$options': 'i'}
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

        if stream:
            # Find auctions that match the stream
            auctions = protocols_all_collection.find(
                {'stream': {'$regex': f'.*{re.escape(stream)}.*', '$options': 'i'}})
            auction_client_codes = [auction['code'] for auction in auctions]

            # Filter clients based on these auction codes
            filter_criteria['code'] = {'$in': auction_client_codes}

        total_clients = clients_collection.count_documents(filter_criteria)
        skip = (page - 1) * per_page
        sort_criteria = [('create_date', DESCENDING)]
        documents = list(clients_collection.find(filter_criteria).sort(sort_criteria).skip(skip).limit(per_page))

        sort_by = data.get('sort_by')
        if sort_by:
            reverse_sort = data.get('reverse_sort', False)

            field_type = type(
                next((item for item in documents if item.get(sort_by) not in [None, '', [], {}]), {}).get(sort_by))

            def sort_key(x):
                value = x.get(sort_by)
                if value in [None, '', [], {}]:
                    if issubclass(field_type, datetime.datetime):
                        return datetime.datetime.min if reverse_sort else datetime.datetime.max
                    else:
                        return float('-inf') if reverse_sort else float('inf')
                return value

            documents = sorted(documents, key=sort_key, reverse=reverse_sort)

        start_range = skip + 1
        end_range = min(skip + per_page, total_clients)

        response = Response(json_util.dumps(
            {'clients': documents, 'total_clients': total_clients, 'start_range': start_range, 'end_range': end_range},
            ensure_ascii=False).encode('utf-8'),
                            content_type='application/json;charset=utf-8')
        return response, 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

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


@application.route('/protocols', methods=['POST', 'OPTIONS'])
def protocols():
    if request.method == 'OPTIONS':
        return ("", 204)
    data = request.get_json()
    access_token = data.get('access_token')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    # Extract filter parameters from the request data
    keyword = data.get('keyword')
    auction_date_start = data.get('auction_date_start')
    auction_date_end = data.get('auction_date_end')
    tenderID = data.get('tenderID')
    code = data.get('code')
    newstatus = data.get('newstatus')
    newprotokol_start = data.get('newprotokol_start')
    newprotokol_end = data.get('newprotokol_end')
    protocol_enddate_start = data.get('protocol_enddate_start')
    protocol_enddate_end = data.get('protocol_enddate_end')
    contract_enddate_start = data.get('contract_enddate_start')
    contract_enddate_end = data.get('contract_enddate_end')
    short_name = data.get('short_name')

    # Field to extract from MongoDB documents
    field_name = 'newstatus'
    # List to store unique values from the specified field
    newstatus_list = []
    # Loop through all documents in the collection
    for document in protocols_collection.find():
        # Check if the field exists in the document and if it's not already in the list
        if field_name in document and document[field_name] not in newstatus_list:
            # Add the field value to the list
            newstatus_list.append(document[field_name])

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
        if short_name:
            regex_pattern = f'.*{re.escape(short_name)}.*'
            filter_criteria['short_name'] = {'$regex': regex_pattern, '$options': 'i'}
        if tenderID:
            regex_pattern = f'.*{re.escape(tenderID)}.*'
            filter_criteria['tenderID'] = {'$regex': regex_pattern, '$options': 'i'}
        if code:
            regex_pattern = f'.*{re.escape(code)}.*'
            filter_criteria['code'] = {'$regex': regex_pattern, '$options': 'i'}
        if newstatus:
            regex_pattern = f'.*{re.escape(newstatus)}.*'
            filter_criteria['newstatus'] = {'$regex': regex_pattern, '$options': 'i'}
        if auction_date_start or auction_date_end:
            try:
                start_date = datetime.datetime.strptime(auction_date_start, '%d-%m-%Y')
                print(start_date)
                print(type(start_date))
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(auction_date_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['auction_date'] = {"$gte": start_date, "$lte": end_date}
        if newprotokol_start or newprotokol_end:
            try:
                start_date = datetime.datetime.strptime(newprotokol_start, '%d-%m-%Y')
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(newprotokol_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['newprotokol'] = {"$gte": start_date, "$lte": end_date}
        if protocol_enddate_start or protocol_enddate_end:
            try:
                start_date = datetime.datetime.strptime(protocol_enddate_start, '%d-%m-%Y')
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(protocol_enddate_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['protocol_enddate'] = {"$gte": start_date, "$lte": end_date}
        if contract_enddate_start or contract_enddate_end:
            try:
                start_date = datetime.datetime.strptime(contract_enddate_start, '%d-%m-%Y')
            except TypeError:
                start_date = datetime.datetime.strptime('01-01-2000', '%d-%m-%Y')
            try:
                end_date = datetime.datetime.strptime(contract_enddate_end, '%d-%m-%Y')
            except TypeError:
                end_date = datetime.datetime.strptime('01-01-3000', '%d-%m-%Y')
            filter_criteria['contract_enddate'] = {"$gte": start_date, "$lte": end_date}

        # Count the total number of clients that match the filter criteria
        total_clients = protocols_collection.count_documents(filter_criteria)

        # Paginate the query results using skip and limit, and apply filters
        skip = (page - 1) * per_page
        sort_criteria = [('auction_date', DESCENDING)]
        documents = list(protocols_collection.find(filter_criteria).sort(sort_criteria).skip(skip).limit(per_page))

        # Sorting logic
        sort_by = data.get('sort_by')
        if sort_by:
            reverse_sort = data.get('reverse_sort', False)

            # Determine the type of the field values (assuming non-empty values are of the same type)
            field_type = type(
                next((item for item in documents if item.get(sort_by) not in [None, '', [], {}]), {}).get(sort_by))

            def sort_key(x):
                value = x.get(sort_by)

                # Handle empty values
                if value in [None, '', [], {}]:  # Add other 'empty' indicators if needed
                    if issubclass(field_type, datetime.datetime):
                        return datetime.datetime.min if reverse_sort else datetime.datetime.max
                    else:
                        return float('-inf') if reverse_sort else float('inf')

                return value

            documents = sorted(documents, key=sort_key, reverse=reverse_sort)
        else:
            def custom_sort(document):
                newstatus_value = document.get('newstatus')
                if newstatus_value == "Очікується опублікування протоколу":
                    return 0
                else:
                    return 1

            # Sorting the documents using the custom sorting function
            documents = sorted(documents, key=custom_sort)

        # Calculate the range of clients being displayed
        start_range = skip + 1
        end_range = min(skip + per_page, total_clients)

        for document in documents:
            is_present = comments_collection.find_one({'protocol_id': document['id']})
            if is_present is not None:
                document['comment'] = is_present['comment']

        # Serialize the documents using json_util from pymongo and specify encoding
        response = Response(json_util.dumps({'protocols': documents, 'total_clients': total_clients, 'start_range': start_range, 'end_range': end_range, 'newstatus_list': newstatus_list}, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json;charset=utf-8')
        return response, 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/users_auctions', methods=['POST'])
def users_auctions():
    data = request.get_json()
    access_token = data.get('access_token')

    # Extract filter parameters from the request data
    code = data.get('code')
    if code == '':
        code = ' '

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
        filter_criteria_2 = {}
        if code:
            regex_pattern = f'.*{re.escape(code)}.*'
            filter_criteria['code'] = {'$regex': regex_pattern, '$options': 'i'}
            filter_criteria_2['procuringEntity_id'] = {'$regex': regex_pattern, '$options': 'i'}

        sort_criteria = [('auction_date', DESCENDING)]
        documents = list(protocols_all_collection.find(filter_criteria).sort(sort_criteria))
        documents_2 = list(procuringEntity_auctions_collection.find(filter_criteria_2).sort(sort_criteria))
        documents = documents + documents_2

        # Sorting logic
        sort_by = data.get('sort_by')
        if sort_by:
            reverse_sort = data.get('reverse_sort', False)

            # Determine the type of the field values (assuming non-empty values are of the same type)
            field_type = type(
                next((item for item in documents if item.get(sort_by) not in [None, '', [], {}]), {}).get(sort_by))

            def sort_key(x):
                value = x.get(sort_by)

                # Handle empty values
                if value in [None, '', [], {}]:  # Add other 'empty' indicators if needed
                    if issubclass(field_type, datetime.datetime):
                        return datetime.datetime.min if reverse_sort else datetime.datetime.max
                    else:
                        return float('-inf') if reverse_sort else float('inf')

                return value

            documents = sorted(documents, key=sort_key, reverse=reverse_sort)

        is_biprozorro = biprozorro_test_collection.find_one({'code': code})
        if len(documents) == 0 and is_biprozorro is not None:
            auctions = is_biprozorro['auctions']
            documents = []
            for auction in auctions:
                documents.append({'tenderID': auction})

        # Serialize the documents using json_util from pymongo and specify encoding
        response = Response(json_util.dumps({'auctions': documents}, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json;charset=utf-8')
        return response, 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/add_comment_protocols', methods=['POST'])
def add_comment_protocols():
    data = request.get_json()
    access_token = data.get('access_token')
    protocol_id = data.get('id')
    comment = data.get('comment')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        decoded_token = jwt.decode(access_token, application.config['SECRET_KEY'], algorithms=['HS256'])
        if not protocol_id or not comment:
            response = jsonify({'message': 'Protocol ID or comment is missing'}), 400
            return response

        # Search for the user document by ID and update the 'comment' field
        result = protocols_collection.update_one({'id': protocol_id}, {'$set': {'comment': comment}})

        is_comment = comments_collection.find_one({'protocol_id': protocol_id})
        if is_comment is not None:
            comments_collection.find_one_and_update({'protocol_id': protocol_id}, {'$set': {'comment': comment}})
        elif is_comment is None:
            comments_collection.insert_one({'protocol_id': protocol_id, 'comment': comment})

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


@application.route('/biprozorro', methods=['POST'])
def biprozorro():
    data = request.get_json()
    access_token = data.get('access_token')
    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response
    try:
        # Verify the JWT token
        decoded_token = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Expired token'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response
    name = data.get('name')
    code = data.get('code')
    representative = data.get('representative')
    phone = data.get('phone')
    email = data.get('email')
    auctions = data.get('auctions')
    keyword = data.get('keyword')
    page = data.get('page', 1)
    per_page = data.get('per_page', 10)

    filter_criteria = {}
    if keyword:
        biprozorro_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}
    if name:
        regex_pattern = f'.*{re.escape(name)}.*'
        filter_criteria['name'] = {'$regex': regex_pattern, '$options': 'i'}
    if code:
        regex_pattern = f'.*{re.escape(code)}.*'
        filter_criteria['code'] = {'$regex': regex_pattern, '$options': 'i'}
    if representative:
        regex_pattern = f'.*{re.escape(representative)}.*'
        filter_criteria['representative'] = {'$regex': regex_pattern, '$options': 'i'}
    if phone:
        regex_pattern = f'.*{re.escape(phone)}.*'
        filter_criteria['phone'] = {'$regex': regex_pattern, '$options': 'i'}
    if email:
        regex_pattern = f'.*{re.escape(email)}.*'
        filter_criteria['email'] = {'$regex': regex_pattern, '$options': 'i'}
    if auctions:
        regex_pattern = f'.*{re.escape(auctions)}.*'
        filter_criteria['auctions'] = {'$regex': regex_pattern, '$options': 'i'}

    # Count the total number of clients that match the filter criteria
    total_clients = biprozorro_collection.count_documents(filter_criteria)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(biprozorro_collection.find(filter_criteria).skip(skip).limit(per_page))

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_clients)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'clients': documents, 'total_clients': total_clients, 'start_range': start_range, 'end_range': end_range},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/add_comment_biprozorro', methods=['POST'])
def add_comment_biprozorro():
    data = request.get_json()
    access_token = data.get('access_token')
    code = data.get('code')
    comment = data.get('comment')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        decoded_token = jwt.decode(access_token, application.config['SECRET_KEY'], algorithms=['HS256'])
        if not code or not comment:
            response = jsonify({'message': 'Code or comment is missing'}), 400
            return response

        # Search for the user document by ID and update the 'comment' field
        result = biprozorro_collection.update_one({'code': code}, {'$set': {'comment': comment}})

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


@application.route('/add_mailing_search', methods=['POST'])
def add_mailing_search():
    data = request.get_json()
    access_token = data.get('access_token')
    link = data.get('link')
    name = data.get('name')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        is_present = mailing_search_collection.find_one({'link': link, 'name': name})
        if is_present is None:
            mailing_search_collection.insert_one({'link': link, 'name': name})
            return jsonify({'message': True}), 200
        else:
            return jsonify({'message': False}), 409
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/delete_mailing_search', methods=['POST'])
def delete_mailing_search():
    data = request.get_json()
    access_token = data.get('access_token')
    search_id = data.get('search_id')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        mailing_search_collection.delete_one({'_id': ObjectId(search_id)})
        return jsonify({'message': True}), 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/mailing_search', methods=['POST'])
def mailing_search():
    data = request.get_json()
    access_token = data.get('access_token')
    page = data.get('page', 1)  # Default to page 1 if not provided
    limit = data.get('limit', 10)  # Default to 10 documents per page if not provided

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        # Calculate skip value based on the page and limit
        skip = (page - 1) * limit

        # Get total number of documents
        total_documents = mailing_search_collection.count_documents({})

        # Use the skip and limit values in the find query
        documents = list(mailing_search_collection.find().skip(skip).limit(limit))

        for document in documents:
            document['_id'] = str(document['_id'])

        # Calculate start and end range
        start_range = skip + 1
        end_range = min(skip + limit, total_documents)

        response_data = {
            'documents': documents,
            'total_documents': total_documents,
            'start_range': start_range,
            'end_range': end_range
        }

        response = Response(json_util.dumps(response_data, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json;charset=utf-8')
        return response, 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route("/send_mail", methods=['POST'])
def send_mail():
    data = request.get_json()
    access_token = data.get('access_token')
    subject = data.get('subject')
    recipients = data.get('recipients')
    text = data.get('text')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        for recipient in recipients:
            msg = Message(subject=subject, sender='bagriul@gmail.com', recipients=[recipient])
            msg.body = text
            mail.send(msg)
        return jsonify({'message': True}), 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/new_mailing_list', methods=['POST'])
def new_mailing_list():
    data = request.get_json()
    access_token = data.get('access_token')
    keyword = data.get('keyword')
    stream = data.get('stream')
    min_price = data.get('min_price')
    max_price = data.get('max_price')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        filter_criteria = {}
        if keyword:
            protocols_all_collection.create_index([("$**", "text")])
            filter_criteria['$text'] = {'$search': keyword}
        if stream:
            regex_pattern = f'.*{re.escape(stream)}.*'
            filter_criteria['stream'] = {'$regex': regex_pattern, '$options': 'i'}
        if min_price is not None and max_price is not None:
            filter_criteria['$expr'] = {
                '$and': [
                    {'$gte': [{'$toDouble': '$value_amount'}, min_price]},
                    {'$lte': [{'$toDouble': '$value_amount'}, max_price]}
                ]
            }
        elif min_price is not None:
            filter_criteria['$expr'] = {'$gte': [{'$toDouble': '$value_amount'}, min_price]}
        elif max_price is not None:
            filter_criteria['$expr'] = {'$lte': [{'$toDouble': '$value_amount'}, max_price]}

        documents = list(protocols_all_collection.find(filter_criteria))
        email_list = []
        for document in documents:
            client = clients_collection.find_one({'code': document['code']})
            email = client['login']
            if email not in email_list:
                email_list.append(email)

        return jsonify({'emails': email_list}), 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


@application.route('/mailing_text', methods=['POST'])
def mailing_text():
    data = request.get_json()
    access_token = data.get('access_token')
    tenderID = data.get('tenderID')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    def get_info_from_prozorro(tenderID):
        page = requests.get(f"https://prozorro.sale/auction/{tenderID}/")
        soup = bs(page.content, 'html.parser')
        price_string = soup.find('span', class_='news-card__price-sum news-card__price-sum--large').text
        price_cleaned = ''.join(c for c in price_string if c.isdigit() or c == ',')
        price_cleaned = price_cleaned.replace(',', '.')
        price = float(price_cleaned)
        auction_name = soup.find('h3', class_='information-title').text
        auction_date = soup.find_all('span', class_='auction-info__value')[2].text
        return auction_name, price, auction_date

    auction_name, price, auction_date = get_info_from_prozorro(tenderID)

    text = (f"{auction_name}\n\n"
            f"Початкова вартість – {price} грн.\n"
            f"Дата аукціону – {auction_date}\n\n"
            f"https://sales.tsbgalcontract.org.ua/auction/{tenderID}/")

    return jsonify({'message': text}), 200


@application.route('/get_streams', methods=['POST'])
def get_streams():
    data = request.get_json()
    access_token = data.get('access_token')

    if not access_token:
        response = jsonify({'message': 'Access token is missing'}), 401
        return response

    try:
        documents = list(streams_collection.find())
        response = Response(json_util.dumps(
            {'streams': documents},
            ensure_ascii=False).encode('utf-8'),
                            content_type='application/json;charset=utf-8')
        return response, 200
    except jwt.ExpiredSignatureError:
        response = jsonify({'message': 'Token has expired'}), 401
        return response
    except jwt.InvalidTokenError:
        response = jsonify({'message': 'Invalid token'}), 401
        return response


if __name__ == '__main__':
    application.run(port=5000)

