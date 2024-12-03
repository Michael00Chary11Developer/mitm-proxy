from mitmproxy import http
from ldap3 import Server,Connection,ALL
import base64

LDAP_SERVER="ldap://192.168.10.1"