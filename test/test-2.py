import base64
from mitmproxy import http
from ldap3 import Server, Connection, ALL


LDAP_SERVER = "ldap://192.168.10.1"
BASE_DN = "OU=NPDCO,DC=npdco,DC=local"
LDAP_USER_TEMPLATE = "CN={username},{BASE_DN}"


user_rules = {
    "user1": {"allowed_urls": ["http://trusted.com"]},
    "user2": {"allowed_urls": ["http://safe.com"], "blocked_urls": ["http://blocked.com"]}
}


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


def apply_user_rules(username, flow):
    user_rule = user_rules.get(username)
    if user_rule:
        allowed_urls = user_rule.get("allowed_urls", [])
        blocked_urls = user_rule.get("blocked_urls", [])

 
        if flow.request.url in blocked_urls:
            flow.response = http.Response.make(
                403,
                b"Access Denied: This URL is blocked for your user.",
                {"Content-Type": "text/plain"}
            )
            return

 
        if allowed_urls and flow.request.url not in allowed_urls:
            flow.response = http.Response.make(
                403,
                b"Access Denied: This URL is not allowed for your user.",
                {"Content-Type": "text/plain"}
            )
            return


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
            apply_user_rules(username, flow)
        else:
            flow.response = http.Response.make(
                403,  # Forbidden
                b"Access denied: Invalid username or password.",
                {"Content-Type": "text/plain"}
            )
    else:
        flow.response = http.Response.make(
            401,  # Unauthorized
            b"Access denied: Missing or invalid credentials.",
            {"Content-Type": "text/plain"}
        )
