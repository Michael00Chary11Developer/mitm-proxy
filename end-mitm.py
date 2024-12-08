from mitmproxy import http, ctx
from ldap3 import Server, Connection, ALL, SUBTREE
import base64
import re
from dotenv import load_dotenv
import os
import uuid
import time
from typing import Dict, Optional

load_dotenv()

LDAP_SERVER = os.getenv("LDAP_SERVER")
BASE_DN = os.getenv("BASE_DN")
ADMIN_DN = os.getenv("ADMIN_DN")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

SESSION_DURATION = 86400
session_store: Dict[str, dict] = {}

BYPASS_EXTENSIONS = {'.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.woff', '.woff2'}

USER_CONFIGS = {
    "chary.p": {
        "allowed_domains": ["soft98.ir"],
        "blocked_extensions": ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"],
        "message": b"Only ZIP files are allowed for download from soft98.ir and dl.soft98.ir."
    },
    "kamali.m": {
        "allowed_domains": ["digiboy.ir"],
        "blocked_extensions": ["rar", "exe", "apk", "zip", "tar", "gz", "mp3", "jpg", "png", "img"],
        "message": b"Only ISO files are allowed for download from digiboy.ir."
    },
    "chary.m": {
        "allowed_domains": [],
        "blocked_extensions": ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"],
        "message": b"Only ZIP files are allowed for download.",
        "blocked_domains": ["yasdl.com"]
    }
}

class ProxySession:
    def __init__(self):
        self.authenticated_ips: Dict[str, dict] = {}

    def get_session(self, client_ip: str) -> Optional[dict]:
        if client_ip in self.authenticated_ips:
            session = self.authenticated_ips[client_ip]
            if time.time() < session["expires_at"]:
                return session
            else:
                del self.authenticated_ips[client_ip]
        return None

    def create_session(self, client_ip: str, username: str) -> None:
        self.authenticated_ips[client_ip] = {
            "username": username,
            "created_at": time.time(),
            "expires_at": time.time() + SESSION_DURATION
        }

    def clear_expired_sessions(self) -> None:
        current_time = time.time()
        expired_ips = [ip for ip, session in self.authenticated_ips.items() 
                      if current_time > session["expires_at"]]
        for ip in expired_ips:
            del self.authenticated_ips[ip]

def authenticate_with_ldap(username: str, password: str) -> bool:
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
        return user_conn.bind()
    except Exception as e:
        print(f"LDAP authentication error: {e}")
        return False

def extract_credentials(auth_header: str) -> tuple[Optional[str], Optional[str]]:
    if auth_header and auth_header.startswith("Basic "):
        try:
            encoded_credentials = auth_header[6:]
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            return decoded_credentials.split(":", 1)
        except Exception:
            return None, None
    return None, None

def should_bypass_auth(flow: http.HTTPFlow) -> bool:
    """Check if the request should bypass authentication"""
    url = flow.request.pretty_url.lower()
    return any(url.endswith(ext) for ext in BYPASS_EXTENSIONS)

def process_user_restrictions(flow: http.HTTPFlow, username: str) -> Optional[http.Response]:
    if username not in USER_CONFIGS:
        return None

    config = USER_CONFIGS[username]
    allowed_domains = config["allowed_domains"]
    blocked_extensions = config["blocked_extensions"]
    blocked_domains = config.get("blocked_domains", [])

    if blocked_domains and any(domain in flow.request.host for domain in blocked_domains):
        return http.Response.make(
            403,
            b"Access to this domain is not allowed.",
            {"Content-Type": "text/plain"}
        )

    if allowed_domains:
        if not any(domain in flow.request.host for domain in allowed_domains):
            return None
        
        match = re.search(r'\.([a-zA-Z0-9]+)(\?.*)?$', flow.request.pretty_url)
        if match and match.group(1).lower() in blocked_extensions:
            return http.Response.make(
                403,
                config["message"],
                {"Content-Type": "text/plain"}
            )

    return None

proxy_session = ProxySession()

def request(flow: http.HTTPFlow) -> None:
    if should_bypass_auth(flow):
        return

    client_ip = flow.client_conn.peername[0]
    session = proxy_session.get_session(client_ip)
    if session:
        username = session["username"]
        response = process_user_restrictions(flow, username)
        if response:
            flow.response = response
        return

    auth_header = flow.request.headers.get("Authorization")
    if not auth_header:
        flow.response = http.Response.make(
            401,
            b"Authentication required",
            {
                "WWW-Authenticate": 'Basic realm="LDAP Authentication"',
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache"
            }
        )
        return

    username, password = extract_credentials(auth_header)
    if username and password and authenticate_with_ldap(username, password):
        proxy_session.create_session(client_ip, username)
        response = process_user_restrictions(flow, username)
        if response:
            flow.response = response
        return

    flow.response = http.Response.make(
        401,
        b"Invalid credentials",
        {
            "WWW-Authenticate": 'Basic realm="LDAP Authentication"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache"
        }
    )

def load(loader):
    ctx.proxy_session = ProxySession()

def done():
    pass
