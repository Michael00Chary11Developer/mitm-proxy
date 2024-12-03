from mitmproxy import http
from ldap3 import Server, Connection, ALL
import base64

LDAP_SERVER = "ldap://192.168.10.1"
BASE_DN = "OU=NPDCO,DC=npdco,DC=local" 
LDAP_USER_TEMPLATE = "CN={username},{BASE_DN}" 

def authenticate_with_ldap(username, password):
    try:
    
        user_dn = LDAP_USER_TEMPLATE.format(username=username, BASE_DN=BASE_DN)
    
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        
        return conn.bind()
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
            pass
        else:
            flow.response = http.Response.make(
                403,  
                b"Access denied: LDAP authentication failed.",
                {"Content-Type": "text/plain"}
        )
    else:
        flow.response = http.Response.make(
            401,  
            b"Access denied: Missing or invalid credentials.",
            {"Content-Type": "text/plain"}
        )
