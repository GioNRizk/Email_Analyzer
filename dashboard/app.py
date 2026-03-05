from flask import Flask, render_template, jsonify
import mysql.connector
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT

# Tell Flask exactly where templates folder is
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
app = Flask(__name__, template_folder=template_dir)

def get_db():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        port=DB_PORT
    )

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/emails")
def get_emails():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM email_reports
        WHERE id IN (SELECT MAX(id) FROM email_reports GROUP BY filename)
        ORDER BY final_score DESC
    """)
    emails = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(emails)

@app.route("/api/stats")
def get_stats():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN final_verdict = 'phishing' THEN 1 ELSE 0 END) as phishing,
            SUM(CASE WHEN final_verdict = 'bec' THEN 1 ELSE 0 END) as bec,
            SUM(CASE WHEN final_verdict = 'spam' THEN 1 ELSE 0 END) as spam,
            SUM(CASE WHEN final_verdict = 'benign' THEN 1 ELSE 0 END) as benign,
            SUM(CASE WHEN final_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN final_level = 'HIGH' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN final_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN final_level = 'LOW' THEN 1 ELSE 0 END) as low
        FROM email_reports
        WHERE id IN (SELECT MAX(id) FROM email_reports GROUP BY filename)
    """)
    stats = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(stats)

@app.route("/api/email/<int:email_id>")
def get_email(email_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM email_reports WHERE id = %s", (email_id,))
    email = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(email)

if __name__ == "__main__":
    print("Dashboard running at http://localhost:5000")
    app.run(debug=True, port=5000)