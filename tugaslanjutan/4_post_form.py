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



def csr_enkripsi(text):
    if len(text) > 1 :
        return chr((ord(text[0])-32+3)%95+32) + csr_enkripsi(text[1:])
    else:
        return chr((ord(text[0])-32+3)%95+32)

def csr_dekripsi(text):
    if len(text) > 1:
        return chr((ord(text[0])-32-3)%95+32) + csr_dekripsi(text[1:])
    else:
        return chr((ord(text[0])-32-3)%95+32)


def clmn_transposition_enkripsi(text, key):
    # Mengubah teks menjadi representasi heksadesimal atau base64
    encoded_text = codecs.encode(text.encode('utf-8'), 'hex').decode('utf-8')  # Untuk heksadesimal
    # encoded_text = codecs.encode(text.encode('utf-8'), 'base64').decode('utf-8')  # Untuk base64

    # Menyusun representasi teks menjadi matriks kolom
    columns = len(key)
    rows = (len(encoded_text) + columns - 1) // columns
    matrix = [[''] * columns for _ in range(rows)]
    index = 0
    for i in range(rows):
        for j in range(columns):
            if index < len(encoded_text):
                matrix[i][j] = encoded_text[index]
                index += 1

    # Mengubah urutan kolom berdasarkan kunci
    sorted_columns = sorted(range(columns), key=lambda k: key[k])
    transposed_matrix = [[matrix[i][j] for j in sorted_columns] for i in range(rows)]

    # Menghasilkan ciphertext dari matriks yang diubah
    ciphertext = ''
    for j in range(columns):
        for i in range(rows):
            ciphertext += transposed_matrix[i][j]

    return ciphertext


def clmn_transposition_decipher(ciphertext, key):
    # Menghitung jumlah baris dan kolom berdasarkan panjang ciphertext dan kunci
    columns = len(key)
    rows = len(ciphertext) // columns

    # Mengubah urutan kolom berdasarkan kunci
    sorted_columns = sorted(range(columns), key=lambda k: key[k])

    # Menghasilkan matriks berdasarkan ciphertext dan urutan kolom yang telah diubah
    matrix = [[''] * columns for _ in range(rows)]
    index = 0
    for j in sorted_columns:
        for i in range(rows):
            matrix[i][j] = ciphertext[index]
            index += 1

    # Menggabungkan matriks menjadi teks terenkripsi
    encoded_text = ''
    for i in range(rows):
        for j in range(columns):
            encoded_text += matrix[i][j]

    # Mendekode teks terenkripsi menjadi teks biasa
    plaintext = codecs.decode(encoded_text.encode('utf-8'), 'hex').decode('utf-8')  # Untuk heksadesimal
    # plaintext = codecs.decode(encoded_text.encode('utf-8'), 'base64').decode('utf-8')  # Untuk base64

    return plaintext



def kreate_key():
    p1 = sympy.randprime(2 ** 4, 2 ** 8)
    p2 = sympy.randprime(2 ** 4, 2 ** 8)
    n = p1 * p2

    print("N =", n)

    pn = (p1 - 1) * (p2 - 1)
    e = sympy.randprime(1, pn)
    while math.gcd(e, pn) > 1:
        e = sympy.randprime(1, pn)

    print("Public key =", e)


    d = (pn + 1) / e
    i = 1

    while d % 1 > 0:
        i += 1
        d = (i * pn + 1) / e
    d = int(d)

    print("privat key",d)
    return [n,e,d]
    
	



enkripsitext = ""
def enkripsi(n,p,plain):
    l = math.ceil(math.log2(n))

    plain_byte = bytearray(plain,"utf-8")
    chiper_binary = ""
    for i in plain_byte:
        i = i ** p % n
        chiper_binary += format(i,"0" + str(l) + "b")

    while len(chiper_binary) % 8 > 0:
        chiper_binary += "0"

        #format ke binary ke base64
    chiper_byte = bytearray()
    for x in range(0, len(chiper_binary), 8):
        tmp = chiper_binary[x:x + 8]
        tmp = int(tmp, 2)
        chiper_byte.append(tmp)

    chiper_base64 = base64.b64encode(chiper_byte)

    return chiper_base64.decode("ascii")
    # print("enkripsi message", chiper_base64.decode("ascii"))
	
	



def dekripsi(n,p,chp):
    l = math.ceil(math.log2(n))

    chiper = chp.encode("ascii")
    chiper_byte = base64.b64decode(chiper)
    chiper_binary = ""

    for x in chiper_byte:
        chiper_binary += format(x,"08b")

    #dekirpsi
    plain = ""
    for x in range(0, len(chiper_binary),l):
        x = chiper_binary[x:x + l]
        x = int(x,2)
        plain += chr(x ** p % n)

    return plain
    # print("plain text: ",plain)

	




	

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

	create_dekrip_data = csr_dekripsi(clmn_transposition_decipher(dekripsi(clear_n,int(key),cleaned_text), "139")) 

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
	print(len(asci_text))
	print("Hasil konversi ASCII:", asci_text)



	if asci_text == password:
		print("benar")

	if asci_text == str(password):
		access_token = create_access_token(identity=username)
		print('access_token: ', access_token),
		response = make_response("logged in success")
		kreate_key()
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
	

	kunci = kreate_key()
	create_enrkip_data = enkripsi(kunci[0],kunci[1],clmn_transposition_enkripsi(csr_enkripsi(password), "138"))
	

	conn = get_db_connection()
	cur = conn.cursor()
	strQuery = "INSERT INTO datauser (username,password,n_num) VALUES ('%s','%s',%s)" % (username,create_enrkip_data,kunci[0])
	print(dekripsi(kunci[0],kunci[2],enkripsi(kunci[0],kunci[1],password)))
	cur.execute(strQuery)
	conn.commit()

	return jsonify({"msg":kunci[2]})
		
	
	


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