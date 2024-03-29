from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import os
import psycopg2
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, decode_token, get_jwt_identity
from flask_mail import Mail, Message
from datetime import datetime, timezone

# creating queries
CREATE_USER_TABLE = (
    "CREATE TABLE IF NOT EXISTS \"user\" (id SERIAL PRIMARY KEY, first_name VARCHAR, last_name VARCHAR, email VARCHAR, password VARCHAR, blood_group VARCHAR, ts TIMESTAMP);"
)
CREATE_TRANSACTION_TABLE = (
    """CREATE TABLE IF NOT EXISTS \"transaction\" (transaction_id SERIAL PRIMARY KEY, user_id INTEGER, transaction_type INTEGER, amount REAL, location VARCHAR, ts TIMESTAMP, FOREIGN KEY(user_id) REFERENCES \"user\"(id) ON DELETE CASCADE);"""
)
# type - credit(0), debit(1)
INSERT_NEW_USER = "INSERT INTO \"user\" (first_name, last_name, email, password, blood_group) VALUES (%s, %s, %s, %s, %s) RETURNING id;"
INSERT_NEW_TRANSACTION = "INSERT INTO \"transaction\" (user_id, transaction_type, amount, location, ts) VALUES (%s, %s, %s, %s, %s);"
VERIFY_USER_EXISTENCE = "SELECT EXISTS ( SELECT 1 FROM \"user\" WHERE email LIKE %s AND password LIKE %s);"
VERIFY_USER_LOGGED = "SELECT EXISTS ( SELECT 1 FROM \"user\" WHERE email LIKE %s);"
GET_USER_CRED = "SELECT email, password FROM \"user\" WHERE email LIKE %s;"
UPDATE_USER_PSWD = "UPDATE \"user\" SET password = %s WHERE email = %s;"
GET_USER_ID = "SELECT id FROM \"user\" WHERE email LIKE %s;"
AVAILABLE_UNITS = (
    "SELECT SUM(CASE WHEN transaction_type = 0 THEN amount ELSE 0 END) - SUM(CASE WHEN transaction_type = 1 THEN amount ELSE 0 END) AS difference FROM \"transaction\" WHERE transaction_type IN (0, 1);"
)
USERS_PRESENT = "SELECT count(DISTINCT email) FROM \"user\";"
NO_OF_DONATIONS = "SELECT count(0) FROM \"transaction\";"
NO_OF_BENEFICIARIES = "SELECT count(1) FROM \"transaction\";"
TRANSACTIONS_BY_USER = "SELECT transaction_type, amount, location FROM \"user\", \"transaction\" WHERE email = %s AND \"user\".id=\"transaction\".user_id;"
USER_REGISTRATIONS_EACH_DAY = "SELECT DATE(ts) AS registration_date, COUNT(*) FROM \"user\" GROUP BY DATE(ts) ORDER BY DATE(ts);"
TRANSACTIONS_EACH_DAY = "SELECT DATE(ts) AS transaction_date, COUNT(*) FROM \"transaction\" GROUP BY DATE(ts) ORDER BY DATE(ts);"
NO_OF_DONORS = "SELECT COUNT(DISTINCT user_id) FROM \"transaction\";"

load_dotenv()

app = Flask(__name__)
jwt = JWTManager(app)
mail = Mail(app)
CORS(app)

url = os.getenv('DATABASE_URL')
connection = psycopg2.connect(url)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  # took random guide for temporary basis
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')


@app.route('/endpoints')
def api():
    return jsonify(message="Available end-points", endpoints='/api/register /api/login /api/retrieve_password '
                                                             '/api/update_password /api/process_transaction '
                                                             '/api/remaining_units /api/no_of_users '
                                                             '/api/no_of_donations /api/no_of_beneficiaries '
                                                             '/api/no_of_donors /api/user_transactions')


@app.route('/api/register', methods=['POST'])
def register():
    default_value = None
    fname = request.form.get('fname', default_value)
    lname = request.form.get('lname', default_value)
    email = request.form.get('mail', default_value)
    pswd = request.form.get('pswd', default_value)
    grp = request.form.get('grp', default_value)
    timestamp = datetime.now(timezone.utc)
    
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_USER_TABLE)
            cursor.execute(VERIFY_USER_LOGGED, (email,))
            if cursor.fetchone()[0]:
                return jsonify(message="Email already exists"), 409
            cursor.execute(INSERT_NEW_USER, (fname, lname, email, pswd, grp, timestamp))
            user_id = cursor.fetchone()[0]
    return jsonify(id=user_id, message=f"User {fname, lname} created"), 201


@app.route('/api/login', methods=['POST'])
def login():
    email = request.form.get('mail', None)
    pswd = request.form.get('pswd', None)

    with connection:
        with connection.cursor() as cursor:
            cursor.execute(VERIFY_USER_EXISTENCE, (email, pswd))
            if cursor.fetchone():
                access_token = create_access_token(identity=email)
                return jsonify(message="Login Successful", access_token=access_token), 200
            else:
                return jsonify(message="Invalid credentials"), 401


@app.route('/api/token', methods=['GET'])
def generate_token():
    email = request.form.get('mail', None)
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(VERIFY_USER_LOGGED, (email,))
            if email is not None and cursor:
                return jsonify(access_token=create_access_token(identity=email)), 200
            return jsonify(message="User not found")


@app.route('/api/retrieve_password/<string:email>', methods=['GET'])
def retrieve_password(email: str):
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(VERIFY_USER_LOGGED, (email,))
            if cursor:
                cursor.execute(GET_USER_CRED, (email,))
                msg = Message(
                    "Your password is \"" + cursor.fetchone()[1] + "\" If you haven't requested for password, please "
                                                                   "ignore this mail",
                    sender="admin@dhaan-api.com",
                    recipients=[cursor.fetchone()[0]])
                # msg.subject("API Password")
                mail.send(msg)
                return jsonify(message="Password sent successful"), 200
            else:
                return jsonify(message="Email doesn't exists"), 401


@app.route('/api/update_password', methods=['POST'])
# @jwt_required()
def update_password():
    # jwt_token = request.headers.get('authorization', None)
    # decoded = jwt._decode_jwt_from_config(jwt_token, 'utf-8', False)
    # decoded = decode_token(jwt_token)
    # email = get_jwt_identity()
    email = request.form.get('mail', None)
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(VERIFY_USER_LOGGED, (email,))
            if cursor.fetchone()[0]:
                pswd = request.form.get('pswd', None)
                cursor.execute(GET_USER_CRED, (email,))
                if cursor.fetchone()[1] == pswd:
                    new_pswd = request.form.get('newPswd', None)
                    confirm_pswd = request.form.get('confirm_pswd', None)
                    if new_pswd == confirm_pswd and new_pswd is not None:
                        cursor.execute(UPDATE_USER_PSWD, (new_pswd, email))
                        return jsonify(message="Password updated Successfully"), 202
                    else:
                        return jsonify(message="Passwords doesn't match"), 401
                else:
                    return jsonify(message="Incorrect Password"), 401
            else:
                return jsonify(message="User doesn't exist"), 404


@app.route('/api/process_transaction', methods=['POST'])
@jwt_required()
def process_transaction():
    email = get_jwt_identity()
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_TRANSACTION_TABLE)
            cursor.execute(GET_USER_ID, (email,))
            user_id = cursor.fetchone()[0]
            if user_id:
                transaction_type = request.form.get('type', None)
                amount = request.form.get('amount', None)
                location = request.form.get('location', None)
                timestamp = datetime.now(timezone.utc)
                
                cursor.execute(AVAILABLE_UNITS)
                if transaction_type == '1':
                    if int(amount) < int(cursor.fetchone()[0]):
                        return jsonify(message='Required units not available')
                cursor.execute(INSERT_NEW_TRANSACTION, (user_id, transaction_type, amount, location, timestamp))
                return jsonify(message="Transaction updated Successfully."), 200
            return jsonify(message='User not found'), 401


@app.route('/api/remaining_units', methods=['GET'])
def remaining_units():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(AVAILABLE_UNITS)
            return jsonify(available_units=cursor.fetchone()[0])


@app.route('/api/no_of_users', methods=['GET'])
def no_of_users():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(USERS_PRESENT)
            return jsonify(registered_users=cursor.fetchone()[0])


@app.route('/api/no_of_donations', methods=['GET'])
def no_of_donations():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(NO_OF_DONATIONS)
            return jsonify(donations=cursor.fetchone()[0])


@app.route('/api/no_of_beneficiaries', methods=['GET'])
def no_of_beneficiaries():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(NO_OF_BENEFICIARIES)
            return jsonify(beneficiaries=cursor.fetchone()[0])


@app.route('/api/no_of_donors', methods=['GET'])
def no_of_donors():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(NO_OF_DONORS)
            return jsonify(donors=cursor.fetchone()[0])


@app.route('/api/transactions_per_day', methods=['GET'])
def transactions_per_day():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(TRANSACTIONS_EACH_DAY)
            data = cursor.fetchall()
            data_list = [{"transaction_date": row[0], "count": row[1]} for row in data]
            return jsonify(data_list)


@app.route('/api/registrations_per_day', methods=['GET'])
def registrations_per_day():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(USER_REGISTRATIONS_EACH_DAY)
            data = cursor.fetchall()
            data_list = [{"registration_date": row[0], "count": row[1]} for row in data]
            return jsonify(data_list)


@app.route('/api/user_transactions', methods=['GET'])
def user_transactions():
    email = request.form.get('mail', None)
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(TRANSACTIONS_BY_USER, (email,))
            # lst=[]
            # for i in cursor:
            #     lst.append(i)
            data = cursor.fetchall()
            data_list = [dict(zip([column[0] for column in cursor.description], row)) for row in data]
            return jsonify(data_list)
            

@app.route('/')
def home():
    return render_template('/index.html')


@app.route('/docs')
def docs():
    return render_template('/docs.html')


if __name__ == '__main__':
    app.run()
