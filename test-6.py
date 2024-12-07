# from mitmproxy import http

# allowed_sites = ["example.com", "example.org"]

# def request(flow: http.HTTPFlow) -> None:
    
#     host = flow.request.pretty_host
#     if host not in allowed_sites:
#         flow.response = http.Response.make(
#             403,  
#             b"Access Denied",
#             {"Content-Type": "text/plain"}
        # )


from ldap3 import Server, Connection
from mitmproxy import http


ldap_server = "ldap://ldap.example.com"
ldap_user = "cn=admin,dc=example,dc=com"
ldap_password = "admin_password"


server = Server(ldap_server)
conn = Connection(server, ldap_user, ldap_password)
conn.bind()


conn.search('ou=filter,dc=example,dc=com', '(objectClass=*)', attributes=['allowedDomains'])
allowed_sites = [entry.allowedDomains.value for entry in conn.entries]

def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host

    if host not in allowed_sites:
        flow.response = http.Response.make(
            403,  
            b"Access Denied",
            {"Content-Type": "text/plain"}
        )
