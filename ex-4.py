# from ldap3 import Server, Connection
# from sys import exit


# LDAP_SERVER = "ldap://192.168.10.1:389"
# BASE_DN = "ou=npd,dc=npdco,dc=local"
# USER = f"CN=میکائیل چاری"

# server = Server(LDAP_SERVER)
# connection = Connection(server, BASE_DN)

# try:
#     if not connection.bind():
#         raise Exception("connection was not successful!")
# except Exception as ex:
#     print(f"Error:{ex}")
#     print('defeated!!!')
#     exit(1)

# result = connection.search(
#     BASE_DN, user=USER, attributes=['uid', 'mail'])
# print(result)
import password
from ldap3 import Server, Connection

LDAP_SERVER = "ldap://192.168.10.1:389"
BASE_DN = "OU=NPDCO,DC=npdco,DC=local"
USER_MICHAEL = 'CN=میکائیل چاری,'+BASE_DN
USER_POURYA='CN=پوریا چاری,'+BASE_DN
# user = f"CN=میکائیل چاری,{BASE_DN}"
server = Server(LDAP_SERVER)
connection = Connection(server, user=USER_MICHAEL,
                        password=password.pass_dictianary['michael'])

if connection.bind():
    print('Connection successful!')
else:
    print('Connection failed!')

# try:
#     if not connection.bind():
#         raise Exception('connection was not successful!')
# except Exception as ex:
#     print(f"Error:{ex}")
#     print('defeated!!!')
#     exit(1)

# print("Connection successful!")
