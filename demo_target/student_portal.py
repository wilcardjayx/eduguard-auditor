# Intentionally vulnerable school portal route snippet for EduGuard testing
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/student/grades", methods=["GET"])
def get_student_grades():
    student_id = request.args.get("id")
    conn = sqlite3.connect("school.db")
    cursor = conn.cursor()
    
    # VULN: Unparameterized SQL query (EDU-SAST-001) & missing session ownership check (EDU-RBAC-001)
    query = f"SELECT * FROM grades WHERE student_id = '{student_id}'"
    cursor.execute(query)
    results = cursor.fetchall()
    return jsonify({"grades": results})
