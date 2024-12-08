from mitmproxy import http
from ldap3 import Server, Connection, ALL
import base64


LDAP_SERVER = "ldap://192.168.10.1"
BASE_DN = "ou=NPDCO,dc=npdco,dc=local"
LDAP_FILTER = "(sAMAccountName={})".format("username")


def authenticate_with_ldap(username, password):
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        user_dn = f"CN={username},{BASE_DN}"
        
        conn = Connection(server, user=user_dn, password=password)
        if conn.bind():
            return True
        
        else:
            print(f"Authentication failed for {username}")
            return False
    
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
            401,  # Unauthorized
            b"Access denied: Authentication required.",
            {"WWW-Authenticate": 'Basic realm="LDAP Authentication"'}
        )
        return

    username, password = extract_credentials(authorization_header)

    if username and password:
        if authenticate_with_ldap(username, password):
            pass  # ادامه پردازش درخواست
        else:
            flow.response = http.Response.make(
                403,  # Forbidden
                b"Access denied: LDAP authentication failed.",
                {"Content-Type": "text/plain"}
            )
    else:
        flow.response = http.Response.make(
            401,  # Unauthorized
            b"Access denied: Missing or invalid credentials.",
            {"Content-Type": "text/plain"}
        )