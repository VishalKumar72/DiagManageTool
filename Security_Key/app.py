from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import pandas as pd
import secrets
from datetime import datetime
from pytz import timezone
import smtplib
from email.message import EmailMessage
import xml.etree.ElementTree as ET
import io
import sys
from io import BytesIO
from flashing import analyze_flashing
from dataGeneration import parse_trc_file  # If saved in a separate file
 
 
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong random secret in production
 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'appdata.db')
 
# ---------------------------- TIMEZONE HELPER ---------------------------- #
 
def get_ist_time():
    ist = timezone('Asia/Kolkata')
    return datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')
 
# ---------------------------- DB INITIALIZATION ---------------------------- #
 
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
 
        # Users table - store created_at as TEXT with IST timestamp
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            )
        ''')
 
        # Security keys table - store generated_at as TEXT with IST timestamp
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL,
                ecu TEXT NOT NULL,
                email TEXT NOT NULL,
                sw_part TEXT NOT NULL,
                fixed_code TEXT NOT NULL,
                private_key TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                UNIQUE(project, ecu, sw_part)
            )
        ''')
        # DID table - stores assigned DIDs and related info
         # ...existing code...
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                did_value TEXT UNIQUE NOT NULL,
                short_name TEXT UNIQUE NOT NULL,
                description TEXT,
                data_length INTEGER,
                data_format TEXT,
                resolution TEXT,
                identification INTEGER,
                created_at TEXT NOT NULL
            )
        ''')
        # Add generated_by column if not exists
        cursor.execute("PRAGMA table_info(dids)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'generated_by' not in columns:
            cursor.execute("ALTER TABLE dids ADD COLUMN generated_by TEXT")

        # Create did_requests table for pending DID generation requests
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS did_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_by TEXT NOT NULL,
                short_name TEXT NOT NULL,
                description TEXT,
                data_length INTEGER,
                data_format TEXT,
                resolution TEXT,
                identification INTEGER,
                status TEXT DEFAULT "Pending",
                requested_at TEXT,
                approved_at TEXT
            )
        ''')
       
        # Create default admin user if not exists
        cursor.execute('SELECT * FROM users WHERE email = ?', ('kumar.vishal@tvsmotor.com',))
        if not cursor.fetchone():
            hashed_pw = generate_password_hash('12345678')
            created_at = get_ist_time()
            cursor.execute('INSERT INTO users (email, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)',
               ('kumar.vishal@tvsmotor.com', hashed_pw, created_at, 1))
            print("✅ Default admin user created.")
 
        conn.commit()
 
init_db()
 
# ---------------------------- HELPER FUNCTIONS ---------------------------- #
EXCLUDED_RANGES = [
    (0x0000, 0x00FF),
    (0x0101, 0x01FF),
    (0x0200, 0x02FF),
    (0x0300, 0x03FF),
    (0x0400, 0x04FF),
    (0x0500, 0x05FF),
    (0x0600, 0x06FF),
    (0x0700, 0x07FF),
    (0x0800, 0x08FF),
    (0xA600, 0xA7FF),
    (0xAD00, 0xAFFF),
    (0xB200, 0xBFFF),
    (0xC300, 0xCEFF),
    (0xF000, 0xF00F),
    (0xF180, 0xF19F),
    (0xF1F0, 0xFFFF)
]
 
def is_did_excluded(did_int):
    for low, high in EXCLUDED_RANGES:
        if low <= did_int <= high:
            return True
    return False
 
 
 
 
def generate_next_did():
    """Find the next available DID (4-digit hex) that is not excluded and not already assigned."""
    assigned = set()
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT did_value FROM dids")
        rows = cursor.fetchall()
        for row in rows:
            try:
                # Remove 0x and convert hex to int
                assigned.add(int(row[0], 16))
            except Exception:
                continue
    # Iterate over range 0x0000 to 0xFFFF inclusive
    for i in range(0x0000, 0x10000):
        if is_did_excluded(i):
            continue
        if i in assigned:
            continue
        return f'0x{i:04X}'
    return None  # if no available DID
 
def generate_key_bytes(length):
    """Generate a random hex key of `length` bytes prefixed with '0x'."""
    num = secrets.randbits(length * 8)
    return f'0x{num:0{length * 2}X}'
 
def find_existing_key(sw_part):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT fixed_code, private_key FROM security_keys
            WHERE sw_part = ?
        ''', (sw_part,))
        return cursor.fetchone()
   
def insert_key(project, ecu, email, sw_part, fixed_code, private_key):
    timestamp = get_ist_time()
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_keys (project, ecu, email, sw_part, fixed_code, private_key, generated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (project, ecu, email, sw_part, fixed_code, private_key, timestamp))
            conn.commit()
    except sqlite3.IntegrityError:
        pass
 
#  find_user_by_email function to fetch the is_admin column:
def find_user_by_email(email):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, email, password_hash, is_admin FROM users WHERE email = ?', (email,))
        return cursor.fetchone()
 
def create_user(email, password):
    password_hash = generate_password_hash(password)
    created_at = get_ist_time()
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)', (email, password_hash, created_at))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False
   

# ---------------------------- AUTH ROUTES ---------------------------- #
 
@app.route('/')
def home():
    return redirect('/login')
 
# login route to use the is_admin value from the database:
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        entered_email = request.form['username'].strip().lower()
        entered_password = request.form['password'].strip()
 
        user = find_user_by_email(entered_email)
 
        if user and check_password_hash(user[2], entered_password):
            session['user'] = entered_email
            session['is_admin'] = bool(user[3])
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid email or password.'
 
    return render_template('login.html', error=error)
 
# Add new admin routes to grant or revoke admin privileges:
 
@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
def make_admin(user_id):
    default_admin_email = 'kumar.vishal@tvsmotor.com'
    # Only allow the default admin to make changes
    if session.get('user') != default_admin_email:
        flash("Only the default admin can make admin changes.", "danger")
        return redirect(url_for('admin_dashboard'))
       
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (user_id,))
        conn.commit()
    flash("User is now an admin.", "success")
    return redirect(url_for('admin_dashboard'))
 
@app.route('/admin/remove_admin/<int:user_id>', methods=['POST'])
def remove_admin(user_id):
    default_admin_email = 'kumar.vishal@tvsmotor.com'
    # Only allow the default admin to make changes
    if session.get('user') != default_admin_email:
        flash("Only the default admin can revoke admin privileges.", "danger")
        return redirect(url_for('admin_dashboard'))
       
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Do not allow revoking privileges from the default admin
        cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        if result and result[0] == default_admin_email:
            flash("Default admin privileges cannot be revoked.", "warning")
            return redirect(url_for('admin_dashboard'))
        cursor.execute('UPDATE users SET is_admin = 0 WHERE id = ?', (user_id,))
        conn.commit()
    flash("User is no longer an admin.", "success")
    return redirect(url_for('admin_dashboard'))
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ''
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        confirm = request.form['confirm'].strip()
 
        if password != confirm:
            error = "Passwords do not match"
        elif find_user_by_email(email):
            error = "Email already registered"
        else:
            success = create_user(email, password)
            if success:
                return redirect(url_for('login'))
            else:
                error = "Failed to register user"
 
    return render_template('register.html', error=error)
 
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))
 
# ---------------------------- MAIN PAGES ---------------------------- #
 
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')
 
@app.route('/keygen', methods=['GET', 'POST'])
def run_keygen():
    if 'user' not in session:
        return redirect(url_for('login'))
 
    fixed_code = ''
    private_key = ''
    message = ''
    status = ''
 
    if request.method == 'POST':
        action = request.form.get('action')
        sw_part = request.form.get('sw_part', '').strip()
       
        if action == 'search':
            if not sw_part:
                flash("Please enter a SW Part Number to search.", "error")
            else:
                result = find_existing_key(sw_part)
                if result:
                    # Fetch the owner of this key
                    with sqlite3.connect(DB_FILE) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT email FROM security_keys WHERE sw_part = ?', (sw_part,))
                        owner_row = cursor.fetchone()
                        owner_email = owner_row[0] if owner_row else None
 
                    # Only show keys if user is admin or owner
                    if session.get('is_admin') or session['user'] == owner_email:
                        fixed_code, private_key = result
                    else:
                        fixed_code, private_key = '******', '******'
                    message = "Found keys for this SW Part number."
                    status = "info"
                else:
                    message = "No keys found for this SW Part number."
                    status = "warning"
 
        elif action == 'generate':
            project = request.form.get('project', '').strip()
            ecu = request.form.get('ecu', '').strip()
            email = session['user']
            # sw_part already fetched above
            if not project or not ecu or not email or not sw_part:
                flash("All fields are required for key generation.", "error")
            elif len(sw_part.encode("utf-8")) != 8:
                flash("SW Part Number must be exactly 8 ASCII characters.", "error")
            else:
                result = find_existing_key(sw_part)
                if result:
                    fixed_code, private_key = result
                    message = "Keys already exist for this SW Part number."
                    status = "warning"
                else:
                    fixed_code = generate_key_bytes(8)
                    private_key = generate_key_bytes(16)
                    insert_key(project, ecu, email, sw_part, fixed_code, private_key)
                    message = "Keys generated and saved successfully."
                    status = "success"
 
    return render_template('keygen.html',
                           fixed_code=fixed_code,
                           private_key=private_key,
                           message=message,
                           status=status)
 
# ---------------------------- PLACEHOLDER ROUTES ---------------------------- #
@app.route('/didgen', methods=['GET', 'POST'])
def did_generation():
    if 'user' not in session:
        return redirect(url_for('login'))
       
    message = ''
    status = ''
    generated_did = ''
    search_results = []
    pending_requests = []
 
    # Always fetch pending requests (for the current user) on every call.
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, short_name, description, data_length, data_format, resolution, identification, requested_at 
            FROM did_requests
            WHERE requested_by = ? AND status = 'Pending'
        """, (session['user'],))
        pending_requests = cursor.fetchall()
 
    if request.method == 'POST':
        action = request.form.get('action')
        if not action:
            flash("No action specified.", "error")
            return render_template('didgen.html', message=message, status=status,
                                   generated_did=generated_did, search_results=search_results,
                                   pending_requests=pending_requests)
       
        if action == 'search':
            query = request.form.get('search_short_name', '').strip()
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, did_value, short_name, description, data_length, data_format, resolution, identification, created_at
                    FROM dids
                    WHERE short_name LIKE ?
                """, ('%' + query + '%',))
                search_results = cursor.fetchall()
            if not search_results:
                flash("No DID found matching that short name.", "warning")
       
        elif action == 'generate':
            short_name = request.form.get('short_name', '').strip()
            description = request.form.get('description', '').strip()
            try:
                data_length = int(request.form.get('data_length', ''))
            except ValueError:
                flash("Data Length must be an integer.", "error")
                return render_template('didgen.html', message=message, status=status,
                                       generated_did=generated_did, search_results=search_results,
                                       pending_requests=pending_requests)
            data_format = request.form.get('data_format', '').strip()
            resolution = request.form.get('resolution', '').strip()
            identification = 1 if request.form.get('identification') == 'on' else 0
           
            if not short_name or not data_format:
                flash("Short Name and Data Format are required.", "error")
            else:
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    # Check if a DID with this short name already exists in the generated table.
                    cursor.execute("SELECT id FROM dids WHERE short_name = ?", (short_name,))
                    if cursor.fetchone():
                        flash("A DID with this short name has already been generated.", "warning")
                    else:
                        # Check if a pending request for this short name already exists globally.
                        cursor.execute("SELECT id FROM did_requests WHERE short_name = ? AND status = 'Pending'", (short_name,))
                        if cursor.fetchone():
                            flash("A DID request for this short name is already pending.", "warning")
                        else:
                            requested_at = get_ist_time()
                            cursor.execute('''
                                INSERT INTO did_requests (requested_by, short_name, description, data_length, data_format, resolution, identification, requested_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (session['user'], short_name, description, data_length, data_format, resolution, identification, requested_at))
                            conn.commit()
                            flash("DID generation request submitted and waiting for admin approval.", "info")
                            # Refresh pending_requests after insertion.
                            cursor.execute("""
                                SELECT id, short_name, description, data_length, data_format, resolution, identification, requested_at
                                FROM did_requests
                                WHERE requested_by = ? AND status = 'Pending'
                            """, (session['user'],))
                            pending_requests = cursor.fetchall()
 
    return render_template('didgen.html', message=message, status=status,
                           generated_did=generated_did, search_results=search_results,
                           pending_requests=pending_requests)
 
def ioid_handler():
    return "<h2>IOID Page</h2>"
 
@app.route('/rid')
def rid_handler():
    return "<h2>RID Page</h2>"
 
@app.route('/dtc')
def dtc_handler():
    return "<h2>DTC Page</h2>"
 
@app.route('/flashing')
def flashing_sequences():
    return "<h2>Flashing Sequences Page</h2>"
 
@app.route('/compliance')
def compliance_check():
    return "<h2>Compliance Check Page</h2>"
 
@app.route('/export')
def export_data():
    if not session.get('is_admin'):
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    return render_template('export_data.html')
 
 
@app.route('/admin/export_all')
def export_all():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    # Accept file type, default to odx
    file_type = request.args.get('type', 'odx').lower()
 
    # Fetch generated security keys and DIDs
    with sqlite3.connect(DB_FILE) as conn:
        keys = pd.read_sql_query("SELECT * FROM security_keys", conn)
        dids = pd.read_sql_query("SELECT * FROM dids", conn)
 
    if file_type == "odx":
        # Create XML document
        root = ET.Element('ExportData')
        keys_elem = ET.SubElement(root, 'SecurityKeys')
        for _, row in keys.iterrows():
            key_elem = ET.SubElement(keys_elem, 'SecurityKey')
            for col in keys.columns:
                ET.SubElement(key_elem, col).text = str(row[col])
        dids_elem = ET.SubElement(root, 'DIDs')
        for _, row in dids.iterrows():
            did_elem = ET.SubElement(dids_elem, 'DID')
            for col in dids.columns:
                ET.SubElement(did_elem, col).text = str(row[col])
        tree = ET.ElementTree(root)
        output = BytesIO()
        tree.write(output, encoding='utf-8', xml_declaration=True)
        output.seek(0)
        return send_file(output,
                         download_name='export.odx',
                         as_attachment=True,
                         mimetype='application/xml')
 
    elif file_type == "xlsm":
        output = BytesIO()
        writer = pd.ExcelWriter(output, engine='xlsxwriter')
        keys.to_excel(writer, sheet_name='SecurityKeys', index=False)
        dids.to_excel(writer, sheet_name='DIDs', index=False)
        writer.close()
        output.seek(0)
        return send_file(output,
                     download_name='export.xlsm',
                     as_attachment=True,
                     mimetype='application/vnd.ms-excel.sheet.macroEnabled.12')
 
    elif file_type == "pdf":
        from fpdf import FPDF
        pdf = FPDF()
        # Security Keys page
        pdf.add_page()
        pdf.set_font("Arial", size=14)
        pdf.cell(200, 10, txt="Security Keys", ln=True, align='C')
        pdf.set_font("Arial", size=10)
        for index, row in keys.iterrows():
            pdf.multi_cell(0, 10, txt=str(row.to_dict()))
            pdf.ln(1)
        # DIDs page
        pdf.add_page()
        pdf.set_font("Arial", size=14)
        pdf.cell(200, 10, txt="DIDs", ln=True, align='C')
        pdf.set_font("Arial", size=10)
        for index, row in dids.iterrows():
            pdf.multi_cell(0, 10, txt=str(row.to_dict()))
            pdf.ln(1)
        output = BytesIO()
        pdf.output(output)
        output.seek(0)
        return send_file(output,
                         download_name='export.pdf',
                         as_attachment=True,
                         mimetype='application/pdf')
    else:
        flash("Invalid export type specified.", "danger")
        return redirect(url_for('export_data'))
 
# ---------------------------- ADMIN ROUTES ---------------------------- #
 
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
 
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
 
    # Include the is_admin flag in the query
    c.execute("SELECT id, email, created_at, is_admin,password_hash FROM users ORDER BY id")
    users = c.fetchall()
 
    c.execute("SELECT id, project, ecu, email, sw_part, fixed_code, private_key, generated_at FROM security_keys ORDER BY id")
    keys = c.fetchall()
   
    c.execute("SELECT id, did_value, short_name, description, data_length, data_format, resolution, identification, created_at,generated_by  FROM dids ORDER BY id")
    dids = c.fetchall()
   
    c.execute("""
        SELECT id, requested_by, short_name, description, data_length, data_format, resolution, identification, requested_at
        FROM did_requests
        WHERE status = "Pending" ORDER BY id
    """)
    did_requests = c.fetchall()
   
  

    conn.close()
   
    return render_template("admin_dashboard.html", users=users, keys=keys, dids=dids, did_requests=did_requests )
 
 
 
@app.route('/download_keys')
def download_keys():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    # Fetch keys from the database
    with sqlite3.connect(DB_FILE) as conn:
        df = pd.read_sql_query(
            "SELECT id, project, ecu, email, sw_part, fixed_code, private_key, generated_at FROM security_keys",
            conn
        )
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='SecurityKeys')
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name='keys.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/download_dids')
def download_dids():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    # Fetch DIDs from the database
    with sqlite3.connect(DB_FILE) as conn:
        df = pd.read_sql_query(
            "SELECT id, did_value, short_name, description, data_length, data_format, resolution, identification, created_at,generated_by  FROM dids",
            conn
        )
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='DIDs')
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name='dids.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
 
 
@app.route('/delete_key/<int:key_id>', methods=['POST'])
def delete_key(key_id):
    if not session.get('is_admin'):
        abort(403)  # Forbidden if not admin
    conn = sqlite3.connect(DB_FILE)
    conn.execute('DELETE FROM security_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    flash('Key deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))
 
 
 
@app.route('/delete_did/<int:did_id>', methods=['POST'])
def delete_did(did_id):
    if not session.get('is_admin'):
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
 
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM dids WHERE id = ?", (did_id,))
    conn.commit()
    conn.close()
    flash("DID deleted successfully", "success")
    return redirect(url_for('admin_dashboard'))
@app.route('/edit_key/<int:key_id>', methods=['GET', 'POST'])
def edit_key(key_id):
    if not session.get('is_admin'):
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
 
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
 
    if request.method == 'POST':
        project = request.form['project'].strip()
        ecu = request.form['ecu'].strip()
        email = request.form['email'].strip()
        sw_part = request.form['sw_part'].strip()
        # You can choose whether to allow editing fixed_code/private_key or not.
        cursor.execute("""
            UPDATE security_keys
            SET project = ?, ecu = ?, email = ?, sw_part = ?
            WHERE id = ?
        """, (project, ecu, email, sw_part, key_id))
        conn.commit()
        conn.close()
        flash("Security key updated successfully", "success")
        return redirect(url_for('admin_dashboard'))
 
    cursor.execute("SELECT id, project, ecu, email, sw_part, fixed_code, private_key, generated_at FROM security_keys WHERE id = ?", (key_id,))
    key = cursor.fetchone()
    conn.close()
 
    if not key:
        flash("Security key not found", "danger")
        return redirect(url_for('admin_dashboard'))
 
    return render_template("edit_key.html", key=key)
 
@app.route('/edit_did/<int:did_id>', methods=['GET', 'POST'])
def edit_did(did_id):
    if not session.get('is_admin'):
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
 
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
 
    if request.method == 'POST':
        did_value = request.form['did_value']
        short_name = request.form['short_name']
        description = request.form['description']
        data_length = request.form['data_length']
        data_format = request.form['data_format']
        resolution = request.form['resolution']
        identification = request.form['identification']
 
        cursor.execute("""
            UPDATE dids
            SET did_value = ?, short_name = ?, description = ?, data_length = ?, data_format = ?, resolution = ?, identification = ?
            WHERE id = ?
        """, (did_value, short_name, description, data_length, data_format, resolution, identification, did_id))
        conn.commit()
        conn.close()
        flash("DID updated successfully", "success")
        return redirect(url_for('admin_dashboard'))
 
    cursor.execute("SELECT * FROM dids WHERE id = ?", (did_id,))
    did = cursor.fetchone()
    conn.close()
 
    if not did:
        flash("DID not found", "danger")
        return redirect(url_for('admin_dashboard'))
 
    return render_template('edit_did.html', did=did)
 
# ...existing code...
@app.route('/search_did', methods=['GET', 'POST'])
def search_did():
    if 'user' not in session:
        return redirect(url_for('login'))
   
    results = []
    query = ""
    if request.method == "POST":
        query = request.form['short_name'].strip()
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, did_value, short_name, description, data_length, data_format, resolution, identification, created_at,
                       (SELECT requested_by FROM did_requests WHERE short_name = dids.short_name AND status = 'Approved' LIMIT 1) as owner
                FROM dids
                WHERE short_name LIKE ?
            """, ('%' + query + '%',))
            results = cursor.fetchall()
        # Hide DID value if not admin or owner
        processed_results = []
        for row in results:
            owner_email = row[9]
            if session.get('is_admin') or session['user'] == owner_email:
                processed_results.append(row[:9])  # Show real DID
            else:
                # Hide did_value
                processed_results.append((row[0], '******') + row[2:9])
        results = processed_results
        if not results:
            flash("No DID found matching that short name.", "warning")
    return render_template('search_did.html', results=results, query=query)
# ...existing code...
 
@app.route('/admin/approve_did/<int:request_id>', methods=['POST'])
def approve_did(request_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Retrieve the pending request
        cursor.execute("""
            SELECT requested_by, short_name, description, data_length, data_format, resolution, identification
            FROM did_requests
            WHERE id = ? AND status = "Pending"
        """, (request_id,))
        req = cursor.fetchone()
        if not req:
            flash("Invalid or already processed request.", "error")
            return redirect(url_for('admin_dashboard'))
        # Generate the next available DID
        generated_did = generate_next_did()
        if not generated_did:
            flash("No available DID could be generated.", "error")
            return redirect(url_for('admin_dashboard'))
        created_at = get_ist_time()
        # Insert the generated DID into the dids table
        cursor.execute('''
            INSERT INTO dids (did_value, short_name, description, data_length, data_format, resolution, identification, created_at, generated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?,?)
        ''', (generated_did, req[1], req[2], req[3], req[4], req[5], req[6], created_at,req[0]))
        # Mark the request as Approved (or remove it from pending)
        approved_at = get_ist_time()
        cursor.execute('''
            UPDATE did_requests
            SET status = "Approved", approved_at = ?
            WHERE id = ?
        ''', (approved_at, request_id))
        conn.commit()
   
   
    flash(f"DID {generated_did} generated and approved.", "success")
    return redirect(url_for('admin_dashboard'))
 
@app.route('/admin/reject_did/<int:request_id>', methods=['POST'])
def reject_did(request_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Verify that the request is pending
        cursor.execute("""
            SELECT id FROM did_requests
            WHERE id = ? AND status = "Pending"
        """, (request_id,))
        if not cursor.fetchone():
            flash("Invalid or already processed request.", "error")
            return redirect(url_for('admin_dashboard'))
        rejected_at = get_ist_time()
        cursor.execute("""
            UPDATE did_requests
            SET status = "Rejected", approved_at = ?
            WHERE id = ?
        """, (rejected_at, request_id))
        conn.commit()
    flash("DID request rejected.", "info")
    return redirect(url_for('admin_dashboard'))
# ...existing code...
 
from werkzeug.utils import secure_filename
 
ALLOWED_EXTENSIONS = {'xls', 'xlsx', 'xlsm'}
 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 
@app.route('/admin/import_data', methods=['GET', 'POST'])
def import_data():
    if not session.get('is_admin'):
        flash("Only admins can import data.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        file = request.files.get('file')
        module = request.form.get('module')  # 'dids' or 'security_keys'
        if not file or not allowed_file(file.filename):
            flash("Please upload a valid Excel file.", "danger")
            return redirect(request.url)
        filename = secure_filename(file.filename)
        file_bytes = file.read()

        try:
            df = pd.read_excel(BytesIO(file_bytes))
        except Exception as e:
            flash(f"Error reading Excel file: {e}", "danger")
            return redirect(request.url)

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            if module == 'dids':
                required_cols = {'did_value', 'short_name', 'description', 'data_length', 'data_format', 'resolution', 'identification', 'created_at'}
                if not required_cols.issubset(df.columns):
                    flash("Missing columns for DIDs import.", "danger")
                    return redirect(request.url)
                for _, row in df.iterrows():
                    try:
                        cursor.execute('''
                            INSERT OR IGNORE INTO dids (did_value, short_name, description, data_length, data_format, resolution, identification, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            str(row['did_value']),
                            str(row['short_name']),
                            str(row.get('description', '')),
                            int(row['data_length']),
                            str(row['data_format']),
                            str(row.get('resolution', '')),
                            int(row['identification']),
                            str(row['created_at'])
                        ))
                    except Exception as e:
                        flash(f"Error importing DID: {row.get('short_name', '')} - {e}", "warning")
            elif module == 'security_keys':
                required_cols = {'project', 'ecu', 'email', 'sw_part', 'fixed_code', 'private_key', 'generated_at'}
                if not required_cols.issubset(df.columns):
                    flash("Missing columns for Security Keys import.", "danger")
                    return redirect(request.url)
                for _, row in df.iterrows():
                    try:
                        cursor.execute('''
                            INSERT OR IGNORE INTO security_keys (project, ecu, email, sw_part, fixed_code, private_key, generated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            str(row['project']),
                            str(row['ecu']),
                            str(row['email']),
                            str(row['sw_part']),
                            str(row['fixed_code']),
                            str(row['private_key']),
                            str(row['generated_at'])
                        ))
                    except Exception as e:
                        flash(f"Error importing key: {row.get('sw_part', '')} - {e}", "warning")
            else:
                flash("Invalid module selected.", "danger")
                return redirect(request.url)
            conn.commit()
        flash("Data imported successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('import_data.html')
 
# ...existing code...

@app.route('/log_analyzer', methods=['GET', 'POST'])
def log_analyzer():
    # ...session checks etc...
    log_table = []
    log_filename = None
    analysis_output = None

    if request.method == 'POST':
        file = request.files.get('logfile')
        if file and file.filename:
            log_filename = file.filename
            filepath = os.path.join('uploads', log_filename)
            os.makedirs('uploads', exist_ok=True)
            file.save(filepath)
            # --- Use your parser! ---
            df = parse_trc_file(filepath)
            # Populate log_table for HTML display
            for row in df.itertuples(index=False):
                log_table.append({
                    'message_no': row.message_no,
                    'time_offset': row.time_offset,
                    'type': row.type,
                    'id': row.id,
                    'datalen': row.datalen,
                    'data': ' '.join(row.data)
                })
            # Run flashing analysis and capture output
            buf = io.StringIO()
            sys_stdout = sys.stdout
            try:
                sys.stdout = buf
                if not df.empty:
                    analyze_flashing(df)
                analysis_output = buf.getvalue()
            finally:
                sys.stdout = sys_stdout
        else:
            flash('Please select a log file to upload.', 'warning')

    return render_template(
        'log_analyzer.html',
        log_table=log_table,
        log_filename=log_filename,
        analysis_output=analysis_output
    )


@app.route('/download_log/<filename>')
def download_log(filename):
    return send_file(os.path.join('uploads', filename), as_attachment=True)


# ---------------------------- MAIN ---------------------------- #
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
 