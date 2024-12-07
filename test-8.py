import password
from ldap3 import Server, Connection

LDAP_SERVER = "ldap://192.168.10.1:389"
BASE_DN = "OU=NPDCO,DC=npdco,DC=local"
USER_MICHAEL = 'CN=میکائیل چاری,'+BASE_DN
USER_POURYA = 'CN=پوریا چاری,'+BASE_DN
# user = f"CN=میکائیل چاری,{BASE_DN}"
server = Server(LDAP_SERVER)
connection = Connection(server, user=USER_MICHAEL,
                        password=password.pass_dictianary['michael'])

if connection.bind():
    print('Connection successful!')
else:
    print('Connection failed!')

connection.search(BASE_DN, '(CN=میکائیل چاری)', attributes=['DC', 'mail'])
print(connection.entries)
