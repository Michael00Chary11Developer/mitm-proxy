import base64
import re
import os
import uuid
import time
from mitmproxy import http, ctx
from ldap3 import Server, Connection, ALL, SUBTREE
from typing import Dict, Optional
from dotenv import load_dotenv
from tqdm import tqdm  # Importing tqdm for progress bar

load_dotenv()

LDAP_SERVER = os.getenv("CONF_LDAP_SERVER")
BASE_DN = os.getenv("CONF_BASE_DN")
ADMIN_DN = os.getenv("CONF_ADMIN_DN")
ADMIN_PASSWORD = os.getenv("CONF_ADMIN_PASSWORD")

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
        self.downloads = {}
        self.download_bars = {}

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

    def start_download(self, url: str, total_size: int) -> None:
        """Initialize a tqdm progress bar for the download"""
        self.download_bars[url] = tqdm(total=total_size, unit='B', unit_scale=True, desc=f"Downloading {url}")

    def update_download(self, url: str, chunk_size: int) -> None:
        """Update the progress of the download"""
        if url in self.download_bars:
            self.download_bars[url].update(chunk_size)

    def get_download_progress(self, url: str) -> Optional[Dict[str, int]]:
        """Retrieve the current download progress"""
        if url in self.download_bars:
            bar = self.download_bars[url]
            return {
                "downloaded": bar.n,
                "total_size": bar.total,
                "progress": bar.n / bar.total * 100
            }
        return None

    def stop_download(self, url: str) -> None:
        """Stop tracking the download by closing the progress bar"""
        if url in self.download_bars:
            self.download_bars[url].close()


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
            decoded_credentials = base64.b64decode(
                encoded_credentials).decode("utf-8")
            return decoded_credentials.split(":", 1)
        except Exception:
            return None, None
    return None, None


def should_bypass_auth(flow: http.HTTPFlow) -> bool:
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

    
