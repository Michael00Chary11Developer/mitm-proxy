from mitmproxy import http
import base64


authenticated_users = set()


def extract_credentials(authorization_header):
    if authorization_header and authorization_header.startswith("Basic "):
        encoded_credentials = authorization_header[6:]
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        username, password = decoded_credentials.split(":", 1)
        return username, password
    return None, None


def authenticate(username, password):
    if username == "valid_user" and password == "valid_password":
        return True
    return False


def request(flow: http.HTTPFlow) -> None:
    authorization_header = flow.request.headers.get("Authorization")
    