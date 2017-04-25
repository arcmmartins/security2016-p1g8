from pysqlcipher import dbapi2 as sqlite


class DBUtils():
    conn=None
    users = '''CREATE TABLE IF NOT EXISTS USERS (ID TEXT PRIMARY KEY,name TEXT NOT NULL, cert TEXT NOT NULL, level TEXT NOT NULL DEFAULT '0');'''
    database = 'NEAR! FAR! werever you are! I believe dat my heart will go ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooon'
    # para efeitos de facilidade de teste a password esta inserida automaticamente
    # mas para deployment teria de ser pedida a cada utilizador
    pragmaKey = 'pragma key="security2016p1g8"; pragma kdf_iter=64000;'
    def __init__(self):
        try:
            self.database = 'Sv.db'
            self.conn = sqlite.connect(self.database)
            self.execute(self.users)
        except Exception:
            pass

    def execute(self, sql):
        c = self.conn.cursor()
        c.executescript(self.pragmaKey)
        c.execute(sql)
        self.conn.commit()
        c.close()

    def insertuser(self, data):
        if isinstance(data, list):
            c = self.conn.cursor()
            c.executescript(self.pragmaKey)
            c.execute("""INSERT INTO USERS values (?,?,?,?)""", (str(data[0]), data[1],str(data[2]) ,str(data[3])))
            self.conn.commit()
            c.close()

    def getuser(self, ID):
        ID = str(ID)
        c = self.conn.cursor()
        c.executescript(self.pragmaKey)
        c.execute("""SELECT * FROM USERS WHERE ID={}""".format(ID))
        collumns = [column[0] for column in c.description]
        a = c.fetchall()
        c.close()
        return a

    def updatecert(self, ID , cert):
        c = self.conn.cursor()
        c.executescript(self.pragmaKey)
        c.execute("""UPDATE USERS SET CERT = ? WHERE ID=?""", (str(Cert), str(ID)))
        self.conn.commit()
        c.close()
