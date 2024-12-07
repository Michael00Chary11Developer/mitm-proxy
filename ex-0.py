from ldap3 import Server, Connection, ALL
from mitmproxy import ctx

class LDAPAuthAddon:
    def __init__(self, ldap_server, ldap_user, ldap_password):
        self.server = Server(ldap_server, get_info=ALL)
        self.conn = Connection(self.server, ldap_user, ldap_password, auto_bind=True)

    def request(self, flow):

        user_dn = "uid={},ou=users,dc=example,dc=com".format(flow.request.headers.get("Username"))
        self.conn.search(user_dn, "(objectClass=person)", attributes=["cn", "memberOf"])
        
        if self.conn.entries:
            user_info = self.conn.entries[0]
            ctx.log.info(f"User Info: {user_info}")

            flow.request.headers["X-LDAP-User"] = str(user_info.cn)
        else:
            ctx.log.warn("User not found in LDAP!")

addons = [LDAPAuthAddon("ldap://ldap.example.com", "cn=admin,dc=example,dc=com", "password")]
