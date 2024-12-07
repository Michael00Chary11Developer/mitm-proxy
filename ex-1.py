from ldap3 import Server, Connection

server = Server('ldap://192.168.10.1:389')
connection = Connection(server,'CN=هومن رادمهر,OU=NPDCO,DC=npdco,DC=local',password='P@$$w0rd')

if connection.bind():
    print('Connection successful!')
else:
    print('Connection failed!')
