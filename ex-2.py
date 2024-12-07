# this is sample
# from ldap3 import Server, Connection

# server = Server('ldap://ldap.example.com')
# conn = Connection(server, 'cn=admin,dc=example,dc=com', 'password')
# conn.bind()


# conn.search('ou=users,dc=example,dc=com', '(uid=user1)', attributes=['cn', 'mail'])
# print(conn.entries)


from ldap3 import Server, Connection

server = Server('ldap://192.168.1.10:389')
connection = Connection(Server)
try:
    connection.bind()
except Exception as ex:
    raise ('bind to connection be defeated!!')
