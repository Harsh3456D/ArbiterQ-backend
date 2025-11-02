
#importing necessary libraries

import psycopg2
from psycopg2.extras import DictCursor
from flask import Flask , request , jsonify
from flask_cors import CORS
import cloudinary
import cloudinary.uploader
import os
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import ssl
from email.message import EmailMessage
from flask_socketio import SocketIO, emit
from datetime import datetime

app = Flask(__name__)
CORS(app)
load_dotenv()

# Configure Cloudinary
cloudinary.config(
    cloud_name = os.getenv("CLOUD_NAME"),
    api_key = os.getenv("API_KEY"),
    api_secret = os.getenv("API_SECRET")
)

#establishing the connection to the database
def get_db_connection():
    DATABASE_URL = os.getenv('DATABASE_URL')
    conn = psycopg2.connect(DATABASE_URL)
    return conn

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response


#Sign Up Route
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data['name']
    email = data['email']
    password = data['password']
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        'INSERT INTO "user" (username, email, password) VALUES (%s, %s, %s)',
        (name, email, hashed_password)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'User successfully created'}), 201

# Sign-In route
@app.route('/api/signin', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    cursor.execute('SELECT * FROM "user" WHERE email = %s', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        return jsonify({'message' : 'Login succesful',
            'user': {
                'username': user['username'],
                'email': user['email'],
                'role': user.get('role', 'Student'),
                'uid': user['UID']
            }
        }), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

# Google Sign-In Route
@app.route('/api/google-signin', methods=['POST'])
def google_signin():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Missing token'}), 400
    
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), "468561188665-su6pdv2s2ct5cai7rngs85voj27l6997.apps.googleusercontent.com")
        email = idinfo['email']
        name = idinfo['name']
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT * FROM "user" WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if not user:
            cursor.execute(
                'INSERT INTO "user" (username, email) VALUES (%s, %s)',
                (name, email)
            )
            conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Google sign-in successful'}), 200
        
    except ValueError:
        return jsonify({'error': 'Invalid Google token'}), 401
    except Exception as e:
        return jsonify({'error': 'An internal server error occurred'}), 500

# Feedback Route
@app.route('/api/feedback', methods=['POST'])
def handle_feedback():
    data = request.get_json()
    if not data or 'name' not in data or 'email' not in data or 'message' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    name = data['name']
    from_email = data['email']
    message_text = data['message']
    
    gmail_address = os.getenv("GMAIL_ADDRESS")
    gmail_app_password = os.getenv("GMAIL_APP_PASSWORD")
    
    if not gmail_address or not gmail_app_password:
        return jsonify({'error': 'Server is not configured to send emails.'}), 500
    
    msg = EmailMessage()
    msg['Subject'] = f"New Feedback from {name} via ArbiterQ"
    msg['From'] = gmail_address
    msg['To'] = gmail_address
    msg.set_content(f"You have received new feedback:\n\nFrom: {name} ({from_email})\n\nMessage:\n{message_text}")
    
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(gmail_address, gmail_app_password)
            server.send_message(msg)
        return jsonify({'message': 'Feedback sent successfully!'}), 200
    except Exception as e:
        return jsonify({'error': 'An internal error occurred while sending the message.'}), 500

# ========== POST MANAGEMENT ==========

@app.route('/api/create-post', methods=['POST'])
def create_post():
    topic = request.form.get('topic')
    message = request.form.get('message')
    user_email = request.form.get('user_email')
    attachment_file = request.files.get('attachment')
    
    if not topic or not message or not user_email:
        return jsonify({'error': 'Missing required fields'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID" FROM "user" WHERE email = %s', (user_email,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({'error': 'User not found or not logged in'}), 401
        
        user_id = user_row['UID']
        
        attachment_url = None
        if attachment_file:
            upload_result = cloudinary.uploader.upload(attachment_file)
            attachment_url = upload_result['secure_url']
        
        cursor.execute(
            'INSERT INTO post (user_id, topic, message, attachment_url) VALUES (%s, %s, %s, %s)',
            (user_id, topic, message, attachment_url)
        )
        conn.commit()
        
        return jsonify({'message': 'Post created successfully'}), 201
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'An internal server error occurred'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/posts', methods=['GET'])
def get_posts():
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT p.id, p.user_id, p.topic, p.message, p.attachment_url, p.created_at, u.username FROM post p LEFT JOIN "user" u ON p.user_id = u."UID" ORDER BY p.created_at DESC')
        
        posts = cursor.fetchall()
        posts_list = []
        
        for row in posts:
            created_at = row['created_at']
            if created_at:
                created_at = created_at.isoformat()
            
            cursor.execute('SELECT COUNT(*) as count FROM like_post WHERE post_id = %s', (row['id'],))
            like_count = cursor.fetchone()['count']
            
            posts_list.append({
                'id': row['id'],
                'user_id': row['user_id'],
                'topic': row['topic'],
                'message': row['message'],
                'attachment_url': row['attachment_url'],
                'created_at': created_at,
                'username': row['username'] if row['username'] else 'Anonymous',
                'like_count': like_count
            })
        
        return jsonify(posts_list), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to fetch posts: {str(e)}"}), 500
        
    finally:
        if cursor: cursor.close()
        if conn: conn.close()



@app.route('/api/posts/<int:post_id>/delete', methods=['DELETE'])
def delete_post_user(post_id):
    data = request.get_json()
    user_email = data.get('user_email')
    
    if not user_email:
        return jsonify({'error': 'User not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID", role FROM "user" WHERE email = %s', (user_email,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        user_id = user['UID']
        user_role = user['role']
        
        cursor.execute('SELECT user_id FROM post WHERE id = %s', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        
        post_user_id = post['user_id']
        
        if user_id != post_user_id and user_role != 'Admin':
            return jsonify({'error': 'You do not have permission to delete this post'}), 403
        
        cursor.execute('DELETE FROM post WHERE id = %s', (post_id,))
        conn.commit()
        
        return jsonify({'message': 'Post deleted successfully'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to delete post'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ========== COMMENTS ==========

@app.route('/api/posts/<int:post_id>/comments', methods=['GET'])
def get_comments(post_id):
    conn = None
    cursor = None
    
    try:
        print(f"=== GET COMMENTS REQUEST for post_id={post_id} ===")
        
        conn = get_db_connection()
        print("Database connection established")
        
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        print("Cursor created")
        
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'comment'
        """)
        columns = cursor.fetchall()
        print(f"Comment table columns: {[col['column_name'] for col in columns]}")
        
        cursor.execute("""
            SELECT c.id, c.comment_text, c.created_at, c.user_id, u.username 
            FROM comment c 
            LEFT JOIN "user" u ON c.user_id = u."UID" 
            WHERE c.post_id = %s 
            ORDER BY c.created_at DESC
        """, (post_id,))
        
        comments = cursor.fetchall()
        print(f"Fetched {len(comments)} comments from database")
        
        comments_list = []
        
        for row in comments:
            print(f"Processing comment: {dict(row)}")
            
            created_at = row['created_at']
            if created_at:
                created_at = created_at.isoformat()
            
            comments_list.append({
                'id': row['id'],
                'text': row['comment_text'],
                'created_at': created_at,
                'username': row['username'] if row['username'] else 'Anonymous'
            })
        
        print(f"Successfully prepared {len(comments_list)} comments for response")
        return jsonify(comments_list), 200
        
    except Exception as e:
        print(f"❌ ERROR in get_comments: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print("Full traceback:")
        traceback.print_exc()
        return jsonify({'error': f'Failed to fetch comments: {str(e)}'}), 500
        
    finally:
        if cursor: 
            cursor.close()
            print("Cursor closed")
        if conn: 
            conn.close()
            print("Connection closed")

@app.route('/api/posts/<int:post_id>/comments', methods=['POST'])
def post_comment(post_id):
    data = request.get_json()
    text = data.get('text')
    user_email = data.get('user_email')
    
    print(f"=== POST COMMENT REQUEST ===")
    print(f"post_id: {post_id}")
    print(f"user_email: {user_email}")
    print(f"text length: {len(text) if text else 0}")
    
    if not text or not user_email:
        print("❌ Missing required fields")
        return jsonify({'error': 'Missing required fields'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        print("✅ Database connection established")
        
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID" FROM "user" WHERE email = %s', (user_email,))
        user_row = cursor.fetchone()
        
        if not user_row:
            print(f"❌ User not found with email: {user_email}")
            return jsonify({'error': 'User not found'}), 401
        
        user_id = user_row['UID']
        print(f"✅ Found user_id: {user_id}")
        
        cursor.execute("""
            INSERT INTO comment (post_id, user_id, comment_text, created_at) 
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            RETURNING id
        """, (post_id, user_id, text))
        
        new_comment_id = cursor.fetchone()['id']
        conn.commit()
        
        print(f"✅ Comment inserted successfully with id: {new_comment_id}")
        return jsonify({
            'message': 'Comment posted successfully',
            'comment_id': new_comment_id
        }), 201
        
    except Exception as e:
        if conn: 
            conn.rollback()
        print(f"❌ ERROR posting comment: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print("Full traceback:")
        traceback.print_exc()
        return jsonify({'error': f'Failed to post comment: {str(e)}'}), 500
        
    finally:
        if cursor: 
            cursor.close()
        if conn: 
            conn.close()

@app.route('/api/mentors', methods=['GET'])
def get_mentors():
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID", username FROM "user" WHERE role = %s OR role = %s ORDER BY username', ('Mentor', 'Admin'))
        
        mentors = cursor.fetchall()
        mentors_list = [{'UID': m['UID'], 'username': m['username']} for m in mentors]
        
        return jsonify(mentors_list), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch mentors'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/posts/<int:post_id>/assign-mentor', methods=['POST'])
def assign_mentor(post_id):
    data = request.get_json()
    mentor_id = data.get('mentor_id')
    
    if not mentor_id:
        return jsonify({'error': 'Missing mentor_id'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID" FROM "user" WHERE "UID" = %s', (mentor_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'Mentor not found'}), 404
        
        cursor.execute('UPDATE post SET mentor_id = %s WHERE id = %s', (mentor_id, post_id))
        
        conn.commit()
        return jsonify({'message': 'Mentor assigned successfully'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to assign mentor'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ========== LIKE SYSTEM ==========

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
def toggle_like(post_id):
    data = request.get_json()
    user_email = data.get('user_email')
    
    if not user_email:
        return jsonify({'error': 'User not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID" FROM "user" WHERE email = %s', (user_email,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({'error': 'User not found'}), 401
        
        user_id = user_row['UID']
        
        cursor.execute('SELECT id FROM like_post WHERE post_id = %s AND user_id = %s', (post_id, user_id))
        
        existing_like = cursor.fetchone()
        
        if existing_like:
            cursor.execute('DELETE FROM like_post WHERE post_id = %s AND user_id = %s', (post_id, user_id))
            conn.commit()
            action = 'unliked'
        else:
            cursor.execute('INSERT INTO like_post (post_id, user_id) VALUES (%s, %s)', (post_id, user_id))
            conn.commit()
            action = 'liked'
        
        cursor.execute('SELECT COUNT(*) as count FROM like_post WHERE post_id = %s', (post_id,))
        like_count = cursor.fetchone()['count']
        
        return jsonify({
            'message': f'Post {action}',
            'action': action,
            'like_count': like_count
        }), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to like post'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/posts/<int:post_id>/like-status', methods=['GET'])
def get_like_status(post_id):
    user_email = request.args.get('user_email')
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT COUNT(*) as count FROM like_post WHERE post_id = %s', (post_id,))
        like_count = cursor.fetchone()['count']
        
        user_liked = False
        if user_email:
            cursor.execute('SELECT "UID" FROM "user" WHERE email = %s', (user_email,))
            user_row = cursor.fetchone()
            
            if user_row:
                cursor.execute('SELECT id FROM like_post WHERE post_id = %s AND user_id = %s', (post_id, user_row['UID']))
                user_liked = cursor.fetchone() is not None
        
        return jsonify({
            'like_count': like_count,
            'user_liked': user_liked
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get like status'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ========== NOTIFICATIONS ==========

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    user_email = request.args.get('user_email')
    
    if not user_email:
        return jsonify({'error': 'User not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID" FROM "user" WHERE email = %s', (user_email,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({'error': 'User not found'}), 401
        
        user_id = user_row['UID']
        
        cursor.execute('SELECT n.id, n.title, n.message, n.created_at, n.is_read, u.username FROM notification n LEFT JOIN "user" u ON n.from_user_id = u."UID" WHERE n.to_user_id = %s ORDER BY n.created_at DESC', (user_id,))
        
        notifications = cursor.fetchall()
        notifications_list = []
        
        for row in notifications:
            created_at = row['created_at']
            if created_at:
                created_at = created_at.isoformat()
            
            notifications_list.append({
                'id': row['id'],
                'title': row['title'],
                'message': row['message'],
                'created_at': created_at,
                'is_read': row['is_read'],
                'from_user': row['username'] or 'System'
            })
        
        return jsonify(notifications_list), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch notifications'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE notification SET is_read = TRUE WHERE id = %s', (notification_id,))
        
        conn.commit()
        return jsonify({'message': 'Notification marked as read'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to mark as read'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/notifications/count/unread', methods=['GET'])
def get_unread_count():
    user_email = request.args.get('user_email')
    
    if not user_email:
        return jsonify({'error': 'User not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID" FROM "user" WHERE email = %s', (user_email,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({'error': 'User not found'}), 401
        
        user_id = user_row['UID']
        
        cursor.execute('SELECT COUNT(*) as count FROM notification WHERE to_user_id = %s AND is_read = FALSE', (user_id,))
        
        count = cursor.fetchone()['count']
        
        return jsonify({'unread_count': count}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get count'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ========== ADMIN ENDPOINTS ==========

@app.route('/api/admin/verify-admin', methods=['POST'])
def verify_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT * FROM "user" WHERE username = %s OR email = %s', (username, username))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user.get('role') != 'Admin':
            return jsonify({'error': 'Not an admin'}), 403
        
        return jsonify({
            'message': 'Admin verified',
            'user': {
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Verification failed'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    admin_email = request.args.get('admin_email')
    
    if not admin_email:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT role FROM "user" WHERE email = %s', (admin_email,))
        admin = cursor.fetchone()
        
        if not admin or admin['role'] != 'Admin':
            return jsonify({'error': 'Only admins can access this'}), 403
        
        cursor.execute('SELECT "UID", username, email, role FROM "user" ORDER BY username')
        
        users = cursor.fetchall()
        users_list = [{'UID': u['UID'], 'username': u['username'], 'email': u['email'], 'role': u['role']} for u in users]
        
        return jsonify(users_list), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get users'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/admin/promote-user', methods=['POST'])
def promote_user():
    data = request.get_json()
    target_user_id = data.get('user_id')
    new_role = data.get('role')
    admin_email = data.get('admin_email')
    
    if not target_user_id or not new_role or not admin_email:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if new_role not in ['Admin', 'Mentor', 'Student']:
        return jsonify({'error': 'Invalid role'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID", role FROM "user" WHERE email = %s', (admin_email,))
        admin = cursor.fetchone()
        
        if not admin or admin['role'] != 'Admin':
            return jsonify({'error': 'Only admins can promote users'}), 403
        
        cursor.execute('UPDATE "user" SET role = %s WHERE "UID" = %s', (new_role, target_user_id))
        
        conn.commit()
        
        cursor.execute('SELECT email FROM "user" WHERE "UID" = %s', (target_user_id,))
        target_user = cursor.fetchone()
        
        if target_user:
            cursor.execute('INSERT INTO notification (to_user_id, from_user_id, title, message) VALUES (%s, %s, %s, %s)', (target_user_id, admin['UID'], 'Role Update', f'Your role has been updated to {new_role}'))
            conn.commit()
        
        return jsonify({'message': f'User promoted to {new_role}'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to promote user'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/admin/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    data = request.get_json()
    admin_email = data.get('admin_email')
    
    if not admin_email:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT role FROM "user" WHERE email = %s', (admin_email,))
        admin = cursor.fetchone()
        
        if not admin or admin['role'] != 'Admin':
            return jsonify({'error': 'Only admins can delete users'}), 403
        
        cursor.execute('DELETE FROM "user" WHERE "UID" = %s', (user_id,))
        conn.commit()
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to delete user'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/admin/delete-post/<int:post_id>', methods=['DELETE'])
def admin_delete_post(post_id):
    data = request.get_json()
    admin_email = data.get('admin_email')
    
    if not admin_email:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID", role FROM "user" WHERE email = %s', (admin_email,))
        admin = cursor.fetchone()
        
        if not admin or admin['role'] != 'Admin':
            return jsonify({'error': 'Only admins can delete posts'}), 403
        
        cursor.execute('DELETE FROM post WHERE id = %s', (post_id,))
        conn.commit()
        
        return jsonify({'message': 'Post deleted successfully'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to delete post'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/admin/send-notification', methods=['POST'])
def send_notification():
    data = request.get_json()
    title = data.get('title')
    message = data.get('message')
    target_type = data.get('target_type')
    post_id = data.get('post_id')
    admin_email = data.get('admin_email')
    
    if not title or not message or not target_type or not admin_email:
        return jsonify({'error': 'Missing required fields'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID", role FROM "user" WHERE email = %s', (admin_email,))
        admin = cursor.fetchone()
        
        if not admin or admin['role'] != 'Admin':
            return jsonify({'error': 'Only admins can send notifications'}), 403
        
        admin_id = admin['UID']
        target_users = []
        
        if target_type == 'post_likers':
            cursor.execute('SELECT DISTINCT user_id FROM like_post WHERE post_id = %s', (post_id,))
            likers = cursor.fetchall()
            target_users = [liker['user_id'] for liker in likers]
        
        elif target_type == 'post_author':
            cursor.execute('SELECT user_id FROM post WHERE id = %s', (post_id,))
            post = cursor.fetchone()
            if post:
                target_users = [post['user_id']]
        
        elif target_type == 'all_users':
            cursor.execute('SELECT "UID" FROM "user"')
            users = cursor.fetchall()
            target_users = [user['UID'] for user in users]
        
        for user_id in target_users:
            cursor.execute('INSERT INTO notification (to_user_id, from_user_id, title, message) VALUES (%s, %s, %s, %s)', (user_id, admin_id, title, message))
        
        conn.commit()
        
        return jsonify({
            'message': 'Notifications sent',
            'sent_to_count': len(target_users)
        }), 200
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error': 'Failed to send notifications'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ====== Search Page ========

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    search_type = request.args.get('type', 'posts')
    
    print(f"=== SEARCH REQUEST ===")
    print(f"Query: {query}")
    print(f"Type: {search_type}")
    
    if not query:
        return jsonify({'error': 'Query parameter is required'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        if search_type == 'posts':
            cursor.execute("""
                SELECT 
                    p.id, 
                    p.topic, 
                    p.message, 
                    p.attachment_url, 
                    p.created_at, 
                    p.user_id,
                    u.username,
                    (SELECT COUNT(*) FROM like_post WHERE post_id = p.id) as like_count
                FROM post p
                LEFT JOIN "user" u ON p.user_id = u."UID"
                WHERE 
                    LOWER(p.topic) LIKE LOWER(%s) OR 
                    LOWER(p.message) LIKE LOWER(%s)
                ORDER BY p.created_at DESC
                LIMIT 50
            """, (f'%{query}%', f'%{query}%'))
            
            posts = cursor.fetchall()
            results = []
            
            for post in posts:
                created_at = post['created_at']
                if created_at:
                    created_at = created_at.isoformat()
                
                results.append({
                    'id': post['id'],
                    'topic': post['topic'],
                    'message': post['message'],
                    'attachment_url': post['attachment_url'],
                    'created_at': created_at,
                    'username': post['username'] if post['username'] else 'Anonymous',
                    'like_count': post['like_count']
                })
            
            print(f"Found {len(results)} posts")
            return jsonify(results), 200
            
        elif search_type == 'users':
            cursor.execute("""
                SELECT 
                    "UID", 
                    username, 
                    email, 
                    role, profile_pic
                FROM "user"
                WHERE 
                    LOWER(username) LIKE LOWER(%s) OR 
                    LOWER(email) LIKE LOWER(%s)
                ORDER BY username
                LIMIT 50
            """, (f'%{query}%', f'%{query}%'))
            
            users = cursor.fetchall()
            results = []
            
            for user in users:
                results.append({
                    'UID': user['UID'],
                    'username': user['username'],
                    'email': user['email'],
                    'profile_pic': user.get('profile_pic'),
                    'role': user['role'] if user['role'] else 'Student'
                })
            
            print(f"Found {len(results)} users")
            return jsonify(results), 200
            
        else:
            return jsonify({'error': 'Invalid search type'}), 400
            
    except Exception as e:
        print(f"Search error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Search failed'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            
            
@app.route('/api/admin/users/search', methods=['GET'])
def search_admin_users():
    admin_email = request.args.get('admin_email')
    query = request.args.get('query', '').strip()
    
    if not admin_email:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT role FROM "user" WHERE email = %s', (admin_email,))
        admin = cursor.fetchone()
        
        if not admin or admin['role'] != 'Admin':
            return jsonify({'error': 'Only admins can access this'}), 403
        
        if query:
            cursor.execute("""
                SELECT "UID", username, email, role 
                FROM "user" 
                WHERE 
                    LOWER(username) LIKE LOWER(%s) OR 
                    LOWER(email) LIKE LOWER(%s) OR 
                    LOWER(role) LIKE LOWER(%s)
                ORDER BY username
            """, (f'%{query}%', f'%{query}%', f'%{query}%'))
        else:
            cursor.execute('SELECT "UID", username, email, role FROM "user" ORDER BY username')
        
        users = cursor.fetchall()
        users_list = [{'UID': u['UID'], 'username': u['username'], 'email': u['email'], 'role': u['role']} for u in users]
        
        return jsonify(users_list), 200
        
    except Exception as e:
        print(f"Search users error: {str(e)}")
        return jsonify({'error': 'Failed to search users'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/search/suggestions', methods=['GET'])
def search_suggestions():
    query = request.args.get('query', '').strip()
    
    if not query or len(query) < 2:
        return jsonify([]), 200
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("""
            SELECT DISTINCT topic 
            FROM post 
            WHERE LOWER(topic) LIKE LOWER(%s)
            LIMIT 5
        """, (f'%{query}%',))
        
        suggestions = [row['topic'] for row in cursor.fetchall()]
        return jsonify(suggestions), 200
        
    except Exception as e:
        print(f"Suggestions error: {str(e)}")
        return jsonify([]), 200
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

#======== Profile System =========

@app.route('/api/profile/<user_email>', methods=['GET'])
def get_profile(user_email):
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute('SELECT "UID", username, email, role, profile_pic FROM "user" WHERE email = %s', (user_email,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user's posts
        cursor.execute('''
            SELECT p.id, p.topic, p.message, p.attachment_url, p.created_at,
                   (SELECT COUNT(*) FROM like_post WHERE post_id = p.id) as like_count,
                   (SELECT COUNT(*) FROM comment WHERE post_id = p.id) as comment_count
            FROM post p
            WHERE p.user_id = %s
            ORDER BY p.created_at DESC
        ''', (user['UID'],))
        
        posts = cursor.fetchall()
        posts_list = []
        
        for row in posts:
            created_at = row['created_at'].isoformat() if row['created_at'] else None
            posts_list.append({
                'id': row['id'],
                'topic': row['topic'],
                'message': row['message'],
                'attachment_url': row['attachment_url'],
                'created_at': created_at,
                'like_count': row['like_count'],
                'comment_count': row['comment_count']
            })
        
        return jsonify({
            'user': {
                'uid': user['UID'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'profile_pic': user.get('profile_pic')
            },
            'posts': posts_list
        }), 200
        
    except Exception as e:
        print(f"Get profile error: {str(e)}")
        return jsonify({'error': 'Failed to get profile'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Update profile (username and profile pic)
@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    username = request.form.get('username')
    user_email = request.form.get('user_email')
    profile_pic_file = request.files.get('profile_pic')
    
    if not user_email:
        return jsonify({'error': 'User not authenticated'}), 401
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Upload profile pic to Cloudinary if provided
        profile_pic_url = None
        if profile_pic_file:
            upload_result = cloudinary.uploader.upload(profile_pic_file)
            profile_pic_url = upload_result['secure_url']
        
        # Update user
        if profile_pic_url and username:
            cursor.execute('UPDATE "user" SET username = %s, profile_pic = %s WHERE email = %s', 
                          (username, profile_pic_url, user_email))
        elif profile_pic_url:
            cursor.execute('UPDATE "user" SET profile_pic = %s WHERE email = %s', 
                          (profile_pic_url, user_email))
        elif username:
            cursor.execute('UPDATE "user" SET username = %s WHERE email = %s', 
                          (username, user_email))
        
        conn.commit()
        
        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        print(f"Update profile error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Delete own account (requires password)
@app.route('/api/profile/delete-account', methods=['DELETE'])
def delete_own_account():
    data = request.get_json()
    user_email = data.get('user_email')
    password = data.get('password')
    
    if not user_email or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Verify password
        cursor.execute('SELECT "UID", password FROM "user" WHERE email = %s', (user_email,))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid password'}), 401
        
        # Delete user (cascade will handle posts, comments, likes)
        cursor.execute('DELETE FROM "user" WHERE "UID" = %s', (user['UID'],))
        conn.commit()
        
        return jsonify({'message': 'Account deleted successfully'}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        print(f"Delete account error: {str(e)}")
        return jsonify({'error': 'Failed to delete account'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


if __name__ == '__main__':

    app.run(debug=True, port=5000)
