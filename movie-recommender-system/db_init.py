import sqlite3

connection = sqlite3.connect('database.db')

with open("C:\\Users\\HP\\Desktop\\booksRecommend\\archive\\book-recommender-system\\schema.sql") as f:
    connection.executescript(f.read())

connection.commit()
connection.close()