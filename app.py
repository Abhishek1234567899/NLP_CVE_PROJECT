import sqlite3
import pandas as pd
from flask import Flask, render_template, request

app = Flask(__name__)

# Connect to the database
def get_db_connection():
    conn = sqlite3.connect('cve_data.db')
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    cve_id = request.form['cve_id']
    cve_data = search_cve(cve_id)
    
    if isinstance(cve_data, str):  # In case no result is found (string message)
        return render_template('search_result.html', message=cve_data)
    else:
        # Convert the dataframe to HTML and pass it to the template
        return render_template('search_result.html', cve_data=cve_data.to_html(index=False))

def search_cve(cve_id):
    cve_id = cve_id.strip().upper()  # Convert input to uppercase
    
    # Define the query to fetch data
    query = '''SELECT "CVE ID", "Source Identifier", "Published Date", "Last Modified Date", 
               "Vulnerability Status", "CVSS Score", "Weaknesses", "Configuration", 
               "reference_links", "Category" 
               FROM cve_info WHERE "CVE ID" = ?'''
    
    conn = get_db_connection()
    cve_data = pd.read_sql(query, conn, params=(cve_id,))
    conn.close()
    
    if cve_data.empty:
        return f"No CVE found with the ID: {cve_id}"
    else:
        return cve_data

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)

