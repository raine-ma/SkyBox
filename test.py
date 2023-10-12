import sqlite3  # If using SQLite as an example. Replace with the appropriate library for your database.
import datetime
from flask import Flask, render_template


app = Flask(__name__)

@app.route('/')
def home():
  conn = sqlite3.connect('bruh.db')
  cursor = conn.cursor()
  cursor.execute("SELECT Timeuploaded FROM Attachments")
  data = cursor.fetchall()
  day_counts = {}
  for y in data:
      timeuploaded = y[0]
      day = timeuploaded.split()[0]
      day_counts[day] = day_counts.get(day, 0) + 1

  day_counts = list(day_counts.items())
  num = 0
  filedata = []

  for i in day_counts:
    print('day count: '+str(i[1]))
    filedata.append((i[0], int(i[1]) + num))
    print('total count: '+str(int(i[1]) + num))
    num = int(i[1])+num

  labels = [row[0] for row in filedata]
  values = [row[1] for row in filedata]

  return render_template('graph.html', labels=labels, values=values)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')