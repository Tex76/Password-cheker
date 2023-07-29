import requests as request
from hashlib import sha1
import sys

def pwned_url_check(query_hash):
    url = 'https://api.pwnedpasswords.com/range/' + query_hash
    res = request.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Response you have send {res.status_code}, not valid')
    return res


def password_converter(pas):
    hpas = sha1()
    hpas.update(pas.encode('utf-8'))
    sh1pass = hpas.hexdigest()
    first, rest = sh1pass[:5], sh1pass[5:]
    return [first, rest]


def api_password_checker(password):
    convert = password_converter(password)
    response = pwned_url_check(convert[0]).text
    hashes = (line.split(':') for line in response.splitlines())
    tail = convert[1].upper()
    for hash, count in hashes:
        if hash == tail:
            return count
    return 0



def password_final(password):
    times = api_password_checker(password)
    if times == 0:
        return f"The password: '{password}', is a tough password! good to have\n"
    else:
        return f"The password: '{password}', have been found {times} time keep it away from your accounts!!!\n"


pass_list = sys.argv[1:]
for password in pass_list:
    text = password_final(password)
    print(text)
