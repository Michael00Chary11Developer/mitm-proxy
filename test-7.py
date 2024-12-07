from mitmproxy import http
from ldap3 import Server, Connection, ALL
import base64
import re

LDAP_SERVER = "ldap://192.168.10.1"
BASE_DN = "ou=npdco,dc=npdco,dc=local"


USER_CONFIGS = {
    "میکائیل چاری": {
        "allowed_domains": ["soft98.ir", "dl.soft98.ir", "dl2.soft98.ir"],
        "blocked_extensions": ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"],
        "message": b"Only ZIP files are allowed for download from soft98.ir and dl.soft98.ir."
    },
    "محراب کمالی": {
        "allowed_domains": ["fdn.digiboy.ir", "digiboy.ir"],
        "blocked_extensions": ["rar", "exe", "apk", "zip", "tar", "gz", "mp3", "jpg", "png"],
        "message": b"Only ISO files are allowed for download from digiboy.ir."
    },
}

def authenticate_with_ldap(username, password):
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, user=f"CN={username},{BASE_DN}", password=password, auto_bind=True)
        return conn.bound
    except Exception as e:
        print(f"Error authenticating with LDAP: {e}")
        return False

def extract_credentials(authorization_header):
    if authorization_header and authorization_header.startswith("Basic "):
        encoded_credentials = authorization_header[6:]
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        username, password = decoded_credentials.split(":", 1)
        return username, password
    return None, None

def request(flow: http.HTTPFlow) -> None:
    authorization_header = flow.request.headers.get("Authorization")


    if not authorization_header:
        flow.response = http.Response.make(
            401, 
            b"Access denied: Authentication required.",
            {"WWW-Authenticate": 'Basic realm="LDAP Authentication"'}
        )
        return

    username, password = extract_credentials(authorization_header)

    if username and password:
        if authenticate_with_ldap(username, password):

            if username in USER_CONFIGS:
                user_config = USER_CONFIGS[username]
                allowed_domains = user_config["allowed_domains"]
                blocked_extensions = user_config["blocked_extensions"]
                block_message = user_config["message"]
                

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

        else:
 
            flow.response = http.Response.make(
                401,  # Unauthorized
                b"Invalid credentials. Please try again.",
                {"WWW-Authenticate": 'Basic realm="LDAP Authentication"'}
            )
    else:

        flow.response = http.Response.make(
            401,  # Unauthorized
            b"Access denied: Missing or invalid credentials.",
            {"Content-Type": "text/plain"}
        )
