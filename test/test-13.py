from mitmproxy import http
from ldap3 import Server, Connection, ALL, SUBTREE
import base64
import re
import hashlib
import time
import password

LDAP_SERVER = "ldap://192.168.10.1:389"
BASE_DN = "ou=npdco,dc=npdco,dc=local"

ADMIN_DN = "CN=میکائیل چاری,OU=NPDCO,DC=npdco,DC=local"
ADMIN_PASSWORD = password.pass_dictianary['michael']

USER_CONFIGS = {
    "chary.m": {
        "allowed_domains": ["soft98.ir", "dl.soft98.ir", "dl2.soft98.ir"],
        "blocked_extensions": ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"],
        "message": b"Only ZIP files are allowed for download from soft98.ir and dl.soft98.ir."
    },
    "chary.p": {
        "allowed_domains": ["soft98.ir", "dl.soft98.ir", "dl2.soft98.ir"],
        "blocked_extensions": ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"],
        "message": b"Only ZIP files are allowed for download from soft98.ir and dl.soft98.ir."
    },
    "kamali.m": {
        "allowed_domains": ["fdn.digiboy.ir", "digiboy.ir"],
        "blocked_extensions": ["rar", "exe", "apk", "zip", "tar", "gz", "mp3", "jpg", "png", "img"],
        "message": b"Only ISO files are allowed for download from digiboy.ir."
    },
}


def set_authenticated_cookie(flow, username):
    session_id = hashlib.sha256(f"{username}{time.time()}".encode('utf-8')).hexdigest()
    flow.response.cookies["session_id"] = session_id
    flow.response.cookies["username"] = username
    return session_id


def check_authenticated_cookie(flow):
    session_id = flow.request.cookies.get("session_id")
    username = flow.request.cookies.get("username")
    
    if session_id and username:

        return True
    return False

def authenticate_with_ldap(username, password):
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        
   
        admin_conn = Connection(server, ADMIN_DN, ADMIN_PASSWORD)
        if not admin_conn.bind():
            return False
        
   
        search_filter = f"(sAMAccountName={username})"
        admin_conn.search(BASE_DN, search_filter, SUBTREE)
        if not admin_conn.entries:
            return False
        

        user_dn = admin_conn.entries[0].entry_dn
        
 
        user_conn = Connection(server, user_dn, password)
        if not user_conn.bind():
            return False
        
        return True
    except Exception as e:
        print(f"Error during LDAP authentication: {e}")
        return False

def extract_credentials(auth_header):
    if auth_header and auth_header.startswith("Basic "):
        try:
            encoded_credentials = auth_header[6:]
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)
            return username, password
        except Exception as e:
            return None, None
    return None, None

def request(flow: http.HTTPFlow) -> None:
 
    if check_authenticated_cookie(flow):
        return
    

    auth_header = flow.request.headers.get("Authorization")
    
    if not auth_header:
        flow.response = http.Response.make(
            401,
            b"Access denied: Authentication required.",
            {"WWW-Authenticate": 'Basic realm="LDAP Authentication"'}
        )
        return


    username, password = extract_credentials(auth_header)

    if username and password and authenticate_with_ldap(username, password):
        if username in USER_CONFIGS:

            set_authenticated_cookie(flow, username)

            config = USER_CONFIGS[username]
            allowed_domains = config["allowed_domains"]
            blocked_extensions = config["blocked_extensions"]
            block_message = config["message"]

            if any(domain in flow.request.host for domain in allowed_domains):
                pretty_url = flow.request.pretty_url
                match = re.search(r'\.([a-zA-Z0-9]+)(\?.*)?$', pretty_url)
                
                if match:
                    file_extension = match.group(1).lower()
                    

                    if file_extension in blocked_extensions:
                        flow.response = http.Response.make(
                            403,  # Forbidden
                            block_message,
                            {"Content-Type": "text/plain"}
                        )
                        return
        return
    else:
        flow.response = http.Response.make(
            401,  # Unauthorized
            b"Invalid credentials. Please try again.",
            {"WWW-Authenticate": 'Basic realm="LDAP Authentication"'}
        )
