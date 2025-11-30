from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import os
import json
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pytz

# Prevent Flask from loading .env file to avoid UnicodeDecodeError
os.environ['FLASK_SKIP_DOTENV'] = '1'

app = Flask(__name__)
app.secret_key = 'R§:d&875er6&U%RV'

# Database setup
try:
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn.cursor()
except Exception as e:
    print(f"Database connection error: {e}")

def initdb():
    try:
        # Create users table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT DEFAULT 'Users',
                datejoin TEXT NOT NULL,
                email TEXT,
                bio TEXT,
                avatar TEXT,
                banner TEXT,
                username_color TEXT
            )
        ''')
        # Check and add columns if they don't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        for column in ['email', 'bio', 'avatar', 'banner', 'username_color']:
            if column not in columns:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {column} TEXT")
        # Create pasts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pasts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                pastname TEXT NOT NULL,
                date TEXT NOT NULL,
                hour TEXT NOT NOT,
                view TEXT NOT NULL,
                pin TEXT NOT NULL,
                ip TEXT NOT NULL,
                email TEXT,
                comments TEXT
            )
        ''')
        # Create followers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS followers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                follower_username TEXT NOT NULL,
                followed_username TEXT NOT NULL,
                follow_date TEXT NOT NULL,
                UNIQUE(follower_username, followed_username),
                FOREIGN KEY(follower_username) REFERENCES users(username),
                FOREIGN KEY(followed_username) REFERENCES users(username)
            )
        ''')
        # Create profile_comments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profile_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_username TEXT NOT NULL,
                author_username TEXT NOT NULL,
                comment TEXT NOT NULL,
                comment_date TEXT NOT NULL,
                hidden BOOLEAN DEFAULT FALSE,
                ip_address TEXT NOT NULL,
                FOREIGN KEY(profile_username) REFERENCES users(username),
                FOREIGN KEY(author_username) REFERENCES users(username)
            )
        ''')
        conn.commit()
    except Exception as e:
        print(f"Database initialization error: {e}")

def getip():
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.environ['REMOTE_ADDR'])

DATA = os.path.join(os.getcwd(), "data")
ADMIN_PASTES = os.path.join(os.getcwd(), "data", "admin")
ANON_PASTES = os.path.join(os.getcwd(), "data", "other")
UPLOADS = os.path.join(os.getcwd(), "static", "uploads")  # Directory for avatars and banners

# Ensure uploads directory exists
if not os.path.exists(UPLOADS):
    os.makedirs(UPLOADS)

try:
    with open(os.path.join(DATA, "template"), "r", encoding="utf-8") as temp_file:
        _DEFAULT_POST_TEMPLATE = temp_file.read()
except FileNotFoundError:
    _DEFAULT_POST_TEMPLATE = ""
    print("Warning: template file not found")

admin_posts_list = []
anon_posts_list = []
pinned_posts_list = []
loosers_list = []

def refreshLoosers():
    global loosers_list
    try:
        with open(os.path.join(DATA, "hol.json"), "r", encoding="utf-8") as file:
            data = json.load(file)
        if len(loosers_list) != len(data.get("loosers", [])):
            loosers_list.clear()
            for looser in data.get("loosers", []):
                if isinstance(looser, dict):
                    loosers_list.append(looser)
    except Exception as e:
        print(f"Error refreshing loosers: {e}")

def refreshAdminPosts():
    global admin_posts_list
    try:
        admin_posts_file_list = os.listdir(ADMIN_PASTES)
        admin_posts_list.clear()
        for admin_post_file_name in admin_posts_file_list:
            admin_post_file_name_path = os.path.join(ADMIN_PASTES, admin_post_file_name)
            admin_post_file_name_stats = os.stat(admin_post_file_name_path)
            admin_posts_list.append({
                "name": admin_post_file_name,
                "size": bytes2KB(admin_post_file_name_stats.st_size),
                "creation_date": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%d-%m-%Y'),
                "creation_time": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%H:%M:%S')
            })
    except Exception as e:
        print(f"Error refreshing admin posts: {e}")

def refreshAnonPosts():
    global anon_posts_list, pinned_posts_list
    try:
        anon_posts_file_list = os.listdir(ANON_PASTES)
        anon_posts_list.clear()
        pinned_posts_list.clear()
        role_order = {
            "Admin": 1,
            "Manager": 2,
            "Mod": 3,
            "Council": 4,
            "Clique": 5,
            "Criminal": 6,
            "VIP": 7,
            "Users": 8
        }
        
        for anon_post_file_name in anon_posts_file_list:
            cursor.execute("SELECT owner, date, hour, view, pin, comments FROM pasts WHERE pastname = ?", (anon_post_file_name,))
            result = cursor.fetchone()
            if result:
                pastownername, date_crt, hour_crt, view, pin, comments = result
                pin = pin == "True" if isinstance(pin, str) else bool(pin)
                cursor.execute("SELECT status FROM users WHERE username = ?", (pastownername,))
                resultg = cursor.fetchone()
                pastownerstatus = resultg[0] if resultg else "anonymous"
                comments = json.loads(comments) if comments else []
            else:
                pastownername = "Anonymous"
                view = "?"
                date_crt = "?"
                hour_crt = "?"
                pin = False
                pastownerstatus = "anonymous"
                comments = []
            
            post_data = {
                "name": anon_post_file_name,
                "pastowner": pastownername,
                "pastownerstatus": pastownerstatus,
                "view": view,
                "creation_date": date_crt,
                "creation_time": hour_crt,
                "pin": pin,
                "comments": comments
            }
            
            if post_data['pin']:
                pinned_posts_list.append(post_data)
            else:
                anon_posts_list.append(post_data)
        
        anon_posts_list.sort(key=lambda x: (x['creation_date'], x['creation_time']), reverse=True)
        pinned_posts_list.sort(key=lambda x: (role_order.get(x['pastownerstatus'], 8), x['creation_date'], x['creation_time']))
    except Exception as e:
        print(f"Error refreshing anon posts: {e}")

def bytes2KB(value):
    return value / 1000

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            confpass = request.form.get('confpass')
            email = request.form.get('email')
            ip_address = getip()

            if password != confpass:
                error = 'Passwords do not match.'
            elif len(username) < 3:
                error = 'Username must be at least 3 characters long.'
            else:
                cursor.execute("SELECT * FROM users WHERE ip_address=?", (ip_address,))
                if cursor.fetchone():
                    error = 'An account is already registered with this IP address.'
                else:
                    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
                    if cursor.fetchone():
                        error = 'Username already exists.'
                    else:
                        hashed_password = generate_password_hash(password)
                        moscow_tz = pytz.timezone('Europe/Moscow')
                        now = datetime.now(moscow_tz)
                        datejoin = now.strftime('%d-%m-%Y %H:%M:%S')
                        cursor.execute(
                            "INSERT INTO users (username, password, ip_address, datejoin, email, status) VALUES (?, ?, ?, ?, ?, ?)",
                            (username, hashed_password, ip_address, datejoin, email, 'Users')
                        )
                        conn.commit()
                        session['username'] = username
                        session.permanent = True
                        return redirect(url_for('index'))
        except Exception as e:
            error = f"Registration error: {str(e)}"
            print(f"Registration error: {e}")
    
    return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error, username=username, status=status)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            session.permanent = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials. Please try again.'
    
    return render_template('login.html', error=error, username=username, status=status)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/")
def index():
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    refreshAnonPosts()
    return render_template('index.html', pinned_posts_list=pinned_posts_list, anon_posts_list=anon_posts_list, username=username, status=status)

@app.route("/new")
def new_paste():
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    return render_template("new.html", username=username, status=status)

@app.route("/users")
def users():
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    try:
        admin_users = conn.execute('SELECT * FROM users WHERE status = "Admin"').fetchall()
        manager_users = conn.execute('SELECT * FROM users WHERE status = "Manager"').fetchall()
        mod_users = conn.execute('SELECT * FROM users WHERE status = "Mod"').fetchall()
        council_users = conn.execute('SELECT * FROM users WHERE status = "Council"').fetchall()
        clique_users = conn.execute('SELECT * FROM users WHERE status = "Clique"').fetchall()
        criminal_users = conn.execute('SELECT * FROM users WHERE status = "Criminal"').fetchall()
        vip_users = conn.execute('SELECT * FROM users WHERE status = "VIP"').fetchall()
        regular_users = conn.execute('SELECT * FROM users WHERE status = "Users"').fetchall()
        return render_template("users.html", 
                            admin_users=admin_users,
                            manager_users=manager_users,
                            mod_users=mod_users,
                            council_users=council_users,
                            clique_users=clique_users,
                            criminal_users=criminal_users,
                            vip_users=vip_users,
                            regular_users=regular_users,
                            username=username,
                            status=status)
    except Exception as e:
        print(f"Error loading users: {e}")
        return render_template("users.html", username=username, status=status)

@app.route("/content")
def content():
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    return render_template("content.html", paste_template_text=_DEFAULT_POST_TEMPLATE, username=username, status=status)

@app.route("/new_paste", methods=['POST'])
def new_paste_form_post():
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    try:
        pasteTitle = str(request.form.get('pasteTitle')).replace("/", "%2F")
        pasteContent = request.form.get('pasteContent')
        if len(pasteTitle) < 3 or len(pasteTitle) > 25:
            error_message = "Title must be between 3 and 25 characters."
            return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=username, status=status)
        if len(pasteContent) < 10 or len(pasteContent) > 25000:
            error_message = "Content must be between 10 and 25,000 characters."
            return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=username, status=status)
        file_path = os.path.join(ANON_PASTES, pasteTitle)
        if os.path.exists(file_path):
            error_message = "This title is already taken. Please choose a different title."
            return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=username, status=status)
        
        ip_address = getip()
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        bdus = cursor.fetchone()
        statusus = bdus[0] if bdus else "Users"
        
        current_datetime = datetime.now()
        cursor.execute("SELECT date, hour FROM pasts WHERE ip = ? ORDER BY date DESC, hour DESC LIMIT 1", (ip_address,))
        last_paste = cursor.fetchone()
        if last_paste:
            last_paste_datetime = datetime.strptime(f"{last_paste[0]} {last_paste[1]}", '%d-%m-%Y %H:%M:%S')
            time_diff = current_datetime - last_paste_datetime
            if time_diff < timedelta(minutes=1) and statusus == 'Users':
                cooldown_seconds = int(60 - time_diff.total_seconds())
                error_message = f"Cooldown! Please wait {cooldown_seconds} seconds."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=username, status=status)
        
        owner = username if username else "Anonymous"
        date_formatted = current_datetime.strftime('%d-%m-%Y')
        hour_formatted = current_datetime.strftime('%H:%M:%S')
        cursor.execute("INSERT INTO pasts (owner, pastname, date, hour, view, pin, ip) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                    (owner, pasteTitle, date_formatted, hour_formatted, 0, 'False', ip_address))
        conn.commit()
        
        with open(os.path.join(ANON_PASTES, pasteTitle), "w", encoding="utf-8") as file:
            file.write(pasteContent)
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Error creating paste: {e}")
        return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=str(e), username=username, status=status)

@app.route('/delete_paste/<paste_name>', methods=['POST'])
def delete_paste(paste_name):
    username = session.get('username')
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    
    if not user_status or user_status[0] not in ['Admin', 'Manager', 'Mod']:
        return redirect(url_for('post', file=paste_name))
    
    cursor.execute("DELETE FROM pasts WHERE pastname = ?", (paste_name,))
    file_path = os.path.join(ANON_PASTES, paste_name)
    try:
        os.remove(file_path)
    except:
        pass
    conn.commit()
    return redirect(url_for('index'))

@app.route('/toggle_pinned/<paste_name>', methods=['POST'])
def toggle_pinned(paste_name):
    username = session.get('username')
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    
    if not user_status or user_status[0] not in ['Admin', 'Manager', 'Mod']:
        return redirect(url_for('post', file=paste_name))
    
    cursor.execute("SELECT pin FROM pasts WHERE pastname = ?", (paste_name,))
    result = cursor.fetchone()
    if result:
        new_status = 'False' if result[0] == 'True' else 'True'
        cursor.execute("UPDATE pasts SET pin = ? WHERE pastname = ?", (new_status, paste_name))
        conn.commit()
    
    return redirect(url_for('post', file=paste_name))

@app.route("/delete_comment/<file>/<comment_date>")
def delete_comment(file, comment_date):
    username = session.get('username')
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    
    if not user_status or user_status[0] not in ['Admin', 'Manager', 'Mod']:
        return redirect(url_for('post', file=file))
    
    cursor.execute("SELECT comments FROM pasts WHERE pastname = ?", (file,))
    result = cursor.fetchone()
    if result:
        comments = json.loads(result[0]) if result[0] else []
        comments = [comment for comment in comments if comment['date'] != comment_date]
        cursor.execute("UPDATE pasts SET comments = ? WHERE pastname = ?", (json.dumps(comments), file))
        conn.commit()
    
    return redirect(url_for('post', file=file))

@app.route("/user/<username>")
def user(username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        return redirect(url_for('index'))
    
    userid, username, _, _, status, joined, _, bio, avatar, banner, username_color = result
    cursor.execute("SELECT * FROM pasts WHERE owner = ?", (username,))
    pastes = cursor.fetchall()
    paste_count = len(pastes)
    
    paste_comments_count = {}
    total_comments = 0
    for paste in pastes:
        paste_id = paste[0]
        cursor.execute("SELECT comments FROM pasts WHERE id = ?", (paste_id,))
        comments_json = cursor.fetchone()[0]
        comments_list = json.loads(comments_json) if comments_json else []
        comment_count = len(comments_list)
        paste_comments_count[paste_id] = comment_count
        total_comments += comment_count
    
    pastes_sorted = sorted(pastes, key=lambda x: (x[3], x[4]), reverse=True)
    
    # Fetch followers and following counts
    cursor.execute("SELECT COUNT(*) FROM followers WHERE followed_username = ?", (username,))
    followers_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM followers WHERE follower_username = ?", (username,))
    following_count = cursor.fetchone()[0]
    
    # Check if the logged-in user is following this profile
    is_following = False
    if session.get('username'):
        cursor.execute("SELECT * FROM followers WHERE follower_username = ? AND followed_username = ?", (session.get('username'), username))
        is_following = cursor.fetchone() is not None
    
    # Fetch profile comments
    cursor.execute("SELECT author_username, comment, comment_date, hidden FROM profile_comments WHERE profile_username = ? ORDER BY comment_date DESC", (username,))
    comments_list = [
        {
            "login": row[0],
            "comment": row[1],
            "date": row[2],
            "hidden": row[3],
            "loginstatus": cursor.execute("SELECT status FROM users WHERE username = ?", (row[0],)).fetchone()[0] if cursor.execute("SELECT status FROM users WHERE username = ?", (row[0],)).fetchone() else "anonymous"
        } for row in cursor.fetchall()
    ]
    
    # Get logged-in user's status
    logged_in_status = None
    if session.get('username'):
        cursor.execute("SELECT status FROM users WHERE username = ?", (session.get('username'),))
        result = cursor.fetchone()
        logged_in_status = result[0] if result else 'Users'
    
    return render_template(
        "profile.html",
        login=username,
        status=status,
        userid=userid,
        joined=joined,
        paste_count=paste_count,
        pastes=[(paste[0], paste[1], paste[2], paste[3], paste[4], paste[5]) for paste in pastes_sorted],
        comments=total_comments,
        paste_comments_count=paste_comments_count,
        username=session.get('username'),
        bio=bio or "",
        avatar=avatar or "https://cdn.doxbin.com/profile_pic/default.jpg",
        banner=banner or "",
        username_color=username_color or "#2A9FD6",
        is_following=is_following,
        followers_count=followers_count,
        following_count=following_count,
        comments_list=comments_list,
        status_logged_in=logged_in_status
    )

@app.route("/settings", methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username')
    cursor.execute("SELECT bio, avatar, banner, username_color, status FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    bio = user_data[0] or ""
    avatar = user_data[1] or "https://cdn.doxbin.com/profile_pic/default.jpg"
    banner = user_data[2] or ""
    username_color = user_data[3] or "#2A9FD6"
    status = user_data[4] or "Users"
    
    if request.method == 'POST':
        try:
            new_username = request.form.get('username')
            new_bio = request.form.get('bio')
            new_username_color = request.form.get('username_color')
            
            # Validate username
            if new_username != username:
                if len(new_username) < 3:
                    return render_template("settings.html", error="Username must be at least 3 characters long.", login=username, bio=bio, avatar=avatar, banner=banner, username_color=username_color, username=username, status=status)
                cursor.execute("SELECT * FROM users WHERE username = ?", (new_username,))
                if cursor.fetchone():
                    return render_template("settings.html", error="Username already exists.", login=username, bio=bio, avatar=avatar, banner=banner, username_color=username_color, username=username, status=status)
            
            # Handle file uploads
            new_avatar = avatar
            if 'avatar' in request.files and request.files['avatar'].filename:
                avatar_file = request.files['avatar']
                if avatar_file and allowed_file(avatar_file.filename):
                    avatar_filename = f"{username}_avatar_{datetime.now().strftime('%Y%m%d%H%M%S')}.{avatar_file.filename.rsplit('.', 1)[1].lower()}"
                    avatar_path = os.path.join(UPLOADS, avatar_filename)
                    avatar_file.save(avatar_path)
                    new_avatar = f"/static/uploads/{avatar_filename}"
            
            new_banner = banner
            if 'banner' in request.files and request.files['banner'].filename:
                banner_file = request.files['banner']
                if banner_file and allowed_file(banner_file.filename):
                    banner_filename = f"{username}_banner_{datetime.now().strftime('%Y%m%d%H%M%S')}.{banner_file.filename.rsplit('.', 1)[1].lower()}"
                    banner_path = os.path.join(UPLOADS, banner_filename)
                    banner_file.save(banner_path)
                    new_banner = f"/static/uploads/{banner_filename}"
            
            # Update database
            cursor.execute(
                "UPDATE users SET username = ?, bio = ?, avatar = ?, banner = ?, username_color = ? WHERE username = ?",
                (new_username, new_bio, new_avatar, new_banner, new_username_color, username)
            )
            conn.commit()
            
            # Update session and related tables if username changed
            if new_username != username:
                session['username'] = new_username
                cursor.execute("UPDATE pasts SET owner = ? WHERE owner = ?", (new_username, username))
                cursor.execute("UPDATE followers SET follower_username = ? WHERE follower_username = ?", (new_username, username))
                cursor.execute("UPDATE followers SET followed_username = ? WHERE followed_username = ?", (new_username, username))
                cursor.execute("UPDATE profile_comments SET profile_username = ? WHERE profile_username = ?", (new_username, username))
                cursor.execute("UPDATE profile_comments SET author_username = ? WHERE author_username = ?", (new_username, username))
                conn.commit()
            
            return redirect(url_for('user', username=new_username))
        except Exception as e:
            print(f"Error updating settings: {e}")
            return render_template("settings.html", error=str(e), login=username, bio=bio, avatar=avatar, banner=banner, username_color=username_color, username=username, status=status)
    
    return render_template("settings.html", login=username, bio=bio, avatar=avatar, banner=banner, username_color=username_color, username=username, status=status)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def add_comment_to_post(file, login, comment):
    msk_tz = pytz.timezone('Europe/Moscow')
    now = datetime.now(msk_tz)
    formatted_date = now.strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("SELECT comments FROM pasts WHERE pastname = ?", (file,))
    result = cursor.fetchone()
    comments = json.loads(result[0]) if result and result[0] else []
    ip_address = getip()
    new_comment = {
        "login": login,
        "date": formatted_date,
        "comment": comment,
        "ip_address": ip_address
    }
    comments.append(new_comment)
    cursor.execute("UPDATE pasts SET comments = ? WHERE pastname = ?", (json.dumps(comments), file))
    conn.commit()

@app.route("/post/<file>")
def post(file):
    filename = os.path.join(ANON_PASTES, file)
    try:
        with open(filename, "r", encoding="utf-8") as filec:
            content = filec.read()
    except:
        return redirect(url_for('index'))
    
    # Fetch paste data and increment view count
    cursor.execute("SELECT owner, date, hour, view, pin, comments FROM pasts WHERE pastname = ?", (file,))
    result = cursor.fetchone()
    
    if result:
        # Increment view count
        new_views = int(result[3]) + 1
        cursor.execute("UPDATE pasts SET view = ? WHERE pastname = ?", (new_views, file))
        conn.commit()
        
        owner, creation_date, creation_time, view, is_pinned, comments = result
        comments = json.loads(comments) if comments else []
    else:
        owner = "Anonymous"
        creation_date = "?"
        creation_time = "?"
        view = "?"
        is_pinned = "False"
        comments = []
    
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        user_status = cursor.fetchone()
        status = user_status[0] if user_status else 'Users'
    
    for comment in comments:
        comment_login = comment.get('login')
        cursor.execute("SELECT status FROM users WHERE username = ?", (comment_login,))
        user_status = cursor.fetchone()
        comment['loginstatus'] = user_status[0] if user_status else "anonymous"
    
    comments.sort(key=lambda x: x['date'], reverse=True)
    return render_template(
        "post.html",
        filename=file,
        ownerpast=owner,
        file_content=content,
        creation_date=creation_date,
        creation_time=creation_time,
        view=new_views if result else view,
        is_pinned=is_pinned,
        comments=comments,
        username=username,
        status=status
    )

@app.route("/post/<file>/add_comment", methods=["POST"])
def add_comment(file):
    username = session.get('username')
    login = username if username else "Anonymous"
    ip_address = getip()
    
    try:
        cursor.execute("SELECT owner, date, hour, view, pin, comments FROM pasts WHERE pastname = ?", (file,))
        result = cursor.fetchone()
        if result:
            owner, creation_date, creation_time, view, is_pinned, comments = result
            comments = json.loads(comments) if comments else []
        else:
            return redirect(url_for('index'))
        
        filename = os.path.join(ANON_PASTES, file)
        with open(filename, "r", encoding="utf-8") as filec:
            content = filec.read()
        
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        bdus = cursor.fetchone()
        statusus = bdus[0] if bdus else "anonymous"
        
        comment = request.form.get("comment")
        if login and comment:
            msk_tz = pytz.timezone('Europe/Moscow')
            now = datetime.now(msk_tz)
            for past_comment in comments:
                comment_ip = past_comment.get('ip_address')
                comment_date = past_comment.get('date')
                comment_datetime = msk_tz.localize(datetime.strptime(comment_date, '%Y-%m-%d %H:%M:%S'))
                time_difference = (now - comment_datetime).total_seconds()
                if comment_ip == ip_address and time_difference < 60 and statusus in ['Users', 'anonymous']:
                    comments = sorted(comments, key=lambda x: x['date'], reverse=True)
                    return render_template(
                        "post.html",
                        filename=file,
                        ownerpast=owner,
                        file_content=content,
                        creation_date=creation_date,
                        creation_time=creation_time,
                        view=view,
                        status=statusus,
                        is_pinned=is_pinned,
                        comments=comments,
                        username=username,
                        error=f"Cooldown! Please wait {int(60 - time_difference)} seconds."
                    )
            add_comment_to_post(file, login, comment)
            return redirect(url_for('post', file=file))
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Error adding comment: {e}")
        return redirect(url_for('index'))

@app.route("/tos")
def tos():
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    try:
        with open(os.path.join(DATA, "tos"), "r", encoding="utf-8") as file:
            filec = file.read()
        return render_template("tos.html", file_content=filec, username=username, status=status)
    except:
        return render_template("tos.html", file_content="Terms of Service not available.", username=username, status=status)

@app.route("/hoa")
def hall_of_loosers():
    username = session.get('username')
    status = None
    if username:
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        status = result[0] if result else 'Users'
    refreshLoosers()
    return render_template("hoa.html", loosers_list=loosers_list, username=username, status=status)

@app.route("/follow/<username>", methods=["POST"])
def follow(username):
    if 'username' not in session:
        return jsonify({"error": "You must be logged in to follow users."}), 403
    
    follower = session.get('username')
    if follower == username:
        return jsonify({"error": "You cannot follow yourself."}), 400
    
    try:
        msk_tz = pytz.timezone('Europe/Moscow')
        follow_date = datetime.now(msk_tz).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "INSERT INTO followers (follower_username, followed_username, follow_date) VALUES (?, ?, ?)",
            (follower, username, follow_date)
        )
        conn.commit()
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"error": "You are already following this user."}), 400
    except Exception as e:
        print(f"Error following user: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/unfollow/<username>", methods=["POST"])
def unfollow(username):
    if 'username' not in session:
        return jsonify({"error": "You must be logged in to unfollow users."}), 403
    
    follower = session.get('username')
    try:
        cursor.execute(
            "DELETE FROM followers WHERE follower_username = ? AND followed_username = ?",
            (follower, username)
        )
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error unfollowing user: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/followers/<username>")
def followers(username):
    try:
        cursor.execute("SELECT follower_username, follow_date, status, username_color FROM followers JOIN users ON follower_username = users.username WHERE followed_username = ?", (username,))
        followers = [
            {"username": row[0], "follow_date": row[1], "status": row[2], "username_color": row[3]}
            for row in cursor.fetchall()
        ]
        return jsonify({"followers": followers})
    except Exception as e:
        print(f"Error fetching followers: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/following/<username>")
def following(username):
    try:
        cursor.execute("SELECT followed_username, follow_date, status, username_color FROM followers JOIN users ON followed_username = users.username WHERE follower_username = ?", (username,))
        following = [
            {"username": row[0], "follow_date": row[1], "status": row[2], "username_color": row[3]}
            for row in cursor.fetchall()
        ]
        return jsonify({"following": following})
    except Exception as e:
        print(f"Error fetching following: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/profile/<username>/add_comment", methods=["POST"])
def add_profile_comment(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    author = session.get('username')
    comment = request.form.get('comment')
    if not comment or len(comment) > 90:
        return redirect(url_for('user', username=username))
    
    try:
        msk_tz = pytz.timezone('Europe/Moscow')
        comment_date = datetime.now(msk_tz).strftime('%Y-%m-%d %H:%M:%S')
        ip_address = getip()
        cursor.execute(
            "INSERT INTO profile_comments (profile_username, author_username, comment, comment_date, ip_address) VALUES (?, ?, ?, ?, ?)",
            (username, author, comment, comment_date, ip_address)
        )
        conn.commit()
        return redirect(url_for('user', username=username))
    except Exception as e:
        print(f"Error adding profile comment: {e}")
        return redirect(url_for('user', username=username))

@app.route("/delete_comment/<username>/<comment_date>")
def delete_profile_comment(username, comment_date):
    if 'username' not in session:
        return redirect(url_for('user', username=username))
    
    cursor.execute("SELECT status FROM users WHERE username = ?", (session.get('username'),))
    user_status = cursor.fetchone()
    if not user_status or user_status[0] not in ['Admin', 'Manager', 'Mod']:
        return redirect(url_for('user', username=username))
    
    try:
        cursor.execute(
            "DELETE FROM profile_comments WHERE profile_username = ? AND comment_date = ?",
            (username, comment_date)
        )
        conn.commit()
        return redirect(url_for('user', username=username))
    except Exception as e:
        print(f"Error deleting profile comment: {e}")
        return redirect(url_for('user', username=username))

if __name__ == "__main__":
    initdb()
    app.run("0.0.0.0", port=8080, debug=True)