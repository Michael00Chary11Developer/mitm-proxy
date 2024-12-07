from mitmproxy import http
from ldap3 import Server, Connection


ldap_server = 'ldap://ldap.example.com'
ldap_dn = 'cn=admin,dc=example,dc=com'
ldap_password = 'password'


server = Server(ldap_server)
conn = Connection(server, ldap_dn, ldap_password)


if not conn.bind():
    print("LDAP connection failed.")
    exit()


def request(flow: http.HTTPFlow):

    username = flow.request.headers.get("Username")
    

    conn.search('dc=example,dc=com', f'(uid={username})', attributes=['uid', 'userRole'])
    
    if conn.entries:
        user_entry = conn.entries[0]
        user_role = user_entry.userRole.value
        
     
        if user_role == 'restricted':
            if "example.com" in flow.request.host:
                flow.response = http.Response.make(
                    403,  
                    b"Access Forbidden",
                    {"Content-Type": "text/plain"}
                )

