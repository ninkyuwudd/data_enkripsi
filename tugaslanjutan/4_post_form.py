import base64
import math
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
    print("plain text: ",plain)




	

@app.route('/')
def homeLogin():
    return render_template('form.html')

@app.route('/login_form')
def loginForm():
    return render_template('form.html')

@app.route("/login_json", methods=["POST"])
def login():
	username = request.json.get('username')
	password = request.json.get('password')
	print('username: ', username)
	print('password: ', password)
	
	conn = get_db_connection()
	cur = conn.cursor()
	cur2 = conn.cursor()

	strQuery = "SELECT * FROM public.user where username='%s' and password='%s';" % (username, password)
	enkrip_data = enkripsi()
	cur2.execute("SELECT password FROM public.user where password = '%s';"%(password))
	filterquery = cur2.fetchone()

	print('strQuery: ',strQuery)
	cur.execute(strQuery)
	user = cur.fetchall()
	
	count = len(user)
	print('count: ', count)

	cleaned_text = filterquery[0].replace("'", "").replace(",", "")
	print(dekripsi(4717,861,cleaned_text))


        
		
	
	if count > 0:
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
	

	conn = get_db_connection()
	cur = conn.cursor()
	strQuery = "INSERT INTO public.user (username,password) VALUES ('%s','%s')" % (username,enkripsi(kunci[0],kunci[1],password))
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
