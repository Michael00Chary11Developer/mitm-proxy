from ldap3 import Server, Connection

LDAP_SERVER = 'ldap://192.168.10.1:389'
BASE_DN = "ou=NPDCO,dc=npdco,dc=local"


def authenticate_with_ldap(username, password):
    try:
        # server = Server(LDAP_SERVER, use_ssl=True)
        server=Server(LDAP_SERVER)
        conn = Connection(
            server, user=f"CN={username},{BASE_DN}", password=password, auto_bind=True)
        return conn.bound
    except Exception as e:
        print(f"Error authenticating with LDAP: {e}")
        return False
