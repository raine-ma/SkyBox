import sqlite3



##NEW SCHEMA MAY 28 "Favorites" ^^ 

conn = sqlite3.connect('final.db')
c = conn.cursor()


c.execute('''
    CREATE TABLE IF NOT EXISTS Attachments (
        ID integer,
        Name text,
        Owner text,
        Size integer,
        Permission integer,
        TimeUploaded integer,
        Salt text,
        Recurses integer,
        Favorites bool,
        Tags text
    )
''')
conn.commit()

