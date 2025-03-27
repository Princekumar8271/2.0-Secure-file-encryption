import os
import webbrowser
import sqlite3
import logging
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from core.auth import AuthenticationManager
from core.file_manager import SecureFileManager
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Initialize managers
auth_manager = AuthenticationManager()
file_manager = SecureFileManager()

@app.route('/')
def index():
    if 'token' in session:
        return redirect(url_for('dashboard'))
    return render_template('explanation.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, token = auth_manager.login(username, password)
        if success:
            session['token'] = token
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials!', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, message = auth_manager.register(username, password)
        if success:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        flash(message, 'error')
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'token' not in session:
        return redirect(url_for('login'))
        
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    try:
        # Get encrypted files for the user
        with sqlite3.connect(file_manager.db_path) as conn:
            cursor = conn.execute("""
                SELECT id, filename, created_at, encrypted 
                FROM files 
                WHERE owner_id = ? 
                ORDER BY created_at DESC
            """, (user_context['user_id'],))
            files = [
                {
                    'id': row[0],
                    'filename': row[1],
                    'date': datetime.fromisoformat(row[2]).strftime('%Y-%m-%d %H:%M'),
                    'encrypted': row[3]
                }
                for row in cursor.fetchall()
            ]
        
        return render_template('dashboard.html', files=files)
        
    except sqlite3.Error as e:
        flash('Error loading files. Please try again.', 'error')
        logging.error(f"Database error: {str(e)}")
        return render_template('dashboard.html', files=[])

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'token' not in session:
        return redirect(url_for('login'))
        
    # Decode token to get user context
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    # Save file temporarily and process
    temp_path = os.path.join('temp', file.filename)
    file.save(temp_path)
    success, message = file_manager.store_file(temp_path, user_context)
    os.remove(temp_path)  # Clean up
    
    flash(message, 'success' if success else 'error')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect(file_manager.db_path) as conn:
            cursor = conn.execute(
                "SELECT filename, file_path FROM files WHERE id = ? AND owner_id = ?",
                (file_id, user_context['user_id'])
            )
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found or access denied.', 'error')
                return redirect(url_for('dashboard'))
            
            filename, file_path = file_info
            return send_file(
                file_path,
                download_name=filename,
                as_attachment=True
            )
    except Exception as e:
        logging.error(f"Download error: {str(e)}")
        flash('Error downloading file.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete/<file_id>', methods=['POST'])
def delete_file(file_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    try:
        # Delete file logic here
        with sqlite3.connect(file_manager.db_path) as conn:
            cursor = conn.execute(
                "SELECT file_path FROM files WHERE id = ? AND owner_id = ?",
                (file_id, user_context['user_id'])
            )
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found or access denied.', 'error')
                return redirect(url_for('dashboard'))
                
            file_path = file_info[0]
            
            # Delete from filesystem
            if os.path.exists(file_path):
                os.remove(file_path)
                
            # Delete from database
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            
            flash('File deleted successfully.', 'success')
            
    except Exception as e:
        logging.error(f"Delete error: {str(e)}")
        flash('Error deleting file.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/explanation')
def explanation():
    return render_template('explanation.html')

if __name__ == '__main__':
    os.makedirs('temp', exist_ok=True)
    webbrowser.open('http://127.0.0.1:5000')  # Opens default browser
    app.run(debug=True)