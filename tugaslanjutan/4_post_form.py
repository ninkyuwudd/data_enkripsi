import base64
import math
import codecs

from flask import Flask
from flask import jsonify
from flask import redirect
from flask import request, render_template,make_response
from flask_cors import CORS
import psycopg2
import sympy
from bcrypt import checkpw
from psycopg2.extras import RealDictCursor

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
CORS(app)
app.config["SECRET_KEY"] = "super-secret" 
jwt = JWTManager(app)

def get_db_connection():
    conn = psycopg2.connect(host='localhost',
                            database='apikelas',
                            user='postgres',
                            password='beginer1383')
    return conn

def generate_key():
    # Menghasilkan kunci acak dengan mengacak urutan karakter alfabet
    import random
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    alphabet_list = list(alphabet)
    random.shuffle(alphabet_list)
    key = ''.join(alphabet_list)
    return key

def encryptsubti(plaintext, key):
    # Mengenkripsi teks menggunakan metode substitusi
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            index = ord(char.lower()) - ord('a')
            encrypted_char = key[index]
            if char.isupper():
                encrypted_char = encrypted_char.upper()
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def decryptsubti(ciphertext, key):
    # Mendekripsi teks menggunakan metode substitusi
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            index = key.index(char.lower())
            decrypted_char = chr(index + ord('a'))
            if char.isupper():
                decrypted_char = decrypted_char.upper()
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext




def encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text


def enkripsibasic(inputtext):
    res = ""
    for i in range(len(inputtext)):
        res += chr((ord(inputtext[i])-32+3)%95+32)
    return res

def decriptbasic(inputchiper):
    res2 = ""
    for i in range(len(inputchiper)):
        res2 += chr((ord(inputchiper[i])-32-3)%95+32)
    return res2




	

@app.route('/')
def homeLogin():
    return render_template('form.html')


@app.route('/login_form')
def loginForm():
    return render_template('form.html')


def text_to_ascii(text):
    ascii_list = []
    for char in text:
        ascii_value = ord(char)
        ascii_list.append(ascii_value)
    return ascii_list


def ascii_to_text(ascii_list):
    text = ""
    for ascii_value in ascii_list:
        if ascii_value != 0: 
            character = chr(ascii_value)
            text += character
    return text


@app.route("/login_json", methods=["POST"])
def login():
	username = request.json.get('username')
	password = request.json.get('password')
	key = request.json.get("key")
	print('username: ', username)
	print('password: ', password)
	print('key : ',key)
	
	conn = get_db_connection()
	cur2 = conn.cursor()
	curn = conn.cursor()

	nQuery = "SELECT n_num FROM datauser where username='%s';" % (username)
	cur2.execute("SELECT password FROM datauser where username = '%s';"%(username))
	curn.execute(nQuery)
	filterquery = cur2.fetchone()
	ndata = curn.fetchone()

	cleaned_text = filterquery[0].replace("'", "").replace(",", "")
	clear_n = ndata[0]
	# clear_pub = ndata[0]

	create_dekrip_data = (decrypt(decryptsubti(decriptbasic(cleaned_text),key), 3))

	print(cleaned_text)
	print(clear_n)
	# print(clear_pub)
	# print(dekripsi(clear_n,int(key),cleaned_text))
	# getpass = dekripsi(clear_n,int(key),cleaned_text)
	print(create_dekrip_data)
	# print(len(getpass))
	print(len(password))

    
	input_text = create_dekrip_data
	ascii_result = text_to_ascii(input_text)
	asci_text = ascii_to_text(ascii_result)
	print(ascii_result)
	print(len(asci_text))
	print("Hasil konversi ASCII:", asci_text)



	if asci_text == password:
		print("benar")

	if asci_text == str(password):
		access_token = create_access_token(identity=username)
		print('access_token: ', access_token),
		response = make_response("logged in success")
		# kreate_key()
		response.set_cookie('access_token',value=access_token,httponly=True)
		return jsonify({"msg": access_token, 'berhasil':1}), 200
	print('Failed...')
	return jsonify({"msg": "Bad username or password", 'success':0})

	

@app.route('/register', methods =['GET', 'POST'])
def register():

	username = request.json.get('username')
	password = request.json.get('password')
	print('username: ', username)
	print('password: ', password)
	

	kunci = generate_key()
	create_enrkip_data = enkripsibasic(encryptsubti(encrypt(password, 3),kunci))
	

	conn = get_db_connection()
	cur = conn.cursor()
	strQuery = "INSERT INTO datauser (username,password,n_num) VALUES ('%s','%s',%s)" % (username,create_enrkip_data,1)
	# print(dekripsi(kunci[0],kunci[2],enkripsi(kunci[0],kunci[1],password)))
	cur.execute(strQuery)
	conn.commit()

	return jsonify({"msg":kunci})
		
	
	


@app.route("/protected/", methods=["POST"])
@jwt_required()
def protected():
    
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200





@app.route("/data_food/", methods=["POST"])
@jwt_required()
def data_makanan():
	conn = get_db_connection()
	cur = conn.cursor()
	query = "select * from public.food"
	cur = conn.cursor(cursor_factory=RealDictCursor)
	cur.execute(query)
	foods = cur.fetchall()
	count = len(foods)
	cur.close()
	conn.close()
	data = {'data_foods': foods, 'success':1}
	return jsonify(data),200


@app.route("/data_drink/", methods=["POST"])
@jwt_required()
def data_drink():
	conn = get_db_connection()
	cur = conn.cursor()
	query = "select * from public.drink"
	cur = conn.cursor(cursor_factory=RealDictCursor)
	cur.execute(query)
	foods = cur.fetchall()
	count = len(foods)
	cur.close()
	conn.close()
	data = {'data_drink': foods, 'success':1}
	return jsonify(data),200


@app.route("/data_user/", methods=["POST"])
@jwt_required()
def data_user():
	conn = get_db_connection()
	cur = conn.cursor()
	strQuery = "select * from public.user"
	print('strQuery: ',strQuery)
	cur = conn.cursor(cursor_factory=RealDictCursor)
	cur.execute(strQuery)
	users = cur.fetchall()
	
	print('users: ', users)
	count = len(users)
	print('count: ', count)

	
	data = {'data_users': users, 'success':1}
	print('data: ', data)
	return jsonify(data), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0')