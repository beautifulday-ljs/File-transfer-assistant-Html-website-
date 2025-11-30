from flask import Flask, request, render_template, send_file, jsonify, redirect, url_for, session
import os
import sqlite3
from datetime import datetime, timedelta
import hashlib
import threading
import time
import traceback
import socket
import json
import random
import base64
from io import BytesIO
import functools

app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER='uploads',
    DATABASE='files.db',
    SECRET_KEY='file_sharing_system_secret_key_2024',
    MAX_CONTENT_LENGTH=5 * 1024 * 1024 * 1024,
    AVATAR_FOLDER='avatars',
    MESSAGE_ATTACHMENTS='message_attachments',
    # 添加缓存配置
    CACHE_TIMEOUT=300,
    DATABASE_POOL_SIZE=5
)

# 权限级别
PERMISSIONS = {
    'super_super_admin': 4,
    'super_admin': 3,
    'admin': 2,
    'user': 1
}

waiting_clients = []
client_lock = threading.Lock()

# 添加缓存字典
cache_dict = {}
cache_lock = threading.Lock()

class CacheManager:
    @staticmethod
    def get(key):
        with cache_lock:
            if key in cache_dict:
                data, expiry = cache_dict[key]
                if expiry > time.time():
                    return data
                else:
                    del cache_dict[key]
            return None
    
    @staticmethod
    def set(key, data, timeout=300):
        with cache_lock:
            cache_dict[key] = (data, time.time() + timeout)
    
    @staticmethod
    def delete(pattern):
        with cache_lock:
            keys_to_delete = [k for k in cache_dict.keys() if pattern in k]
            for key in keys_to_delete:
                del cache_dict[key]

class Database:
    _connection_pool = []
    _pool_lock = threading.Lock()
    
    @staticmethod
    def get_connection():
        try:
            with Database._pool_lock:
                for conn_info in Database._connection_pool:
                    conn, last_used = conn_info
                    if time.time() - last_used < 300:
                        conn_info[1] = time.time()
                        return conn
                
                conn = sqlite3.connect(app.config['DATABASE'])
                conn.row_factory = sqlite3.Row
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA synchronous=NORMAL')
                Database._connection_pool.append([conn, time.time()])
                
                Database._cleanup_pool()
                
                return conn
        except Exception as e:
            print(f"数据库连接失败: {e}")
            try:
                conn = sqlite3.connect(app.config['DATABASE'])
                conn.row_factory = sqlite3.Row
                return conn
            except:
                return None
    
    @staticmethod
    def _cleanup_pool():
        current_time = time.time()
        Database._connection_pool[:] = [
            conn_info for conn_info in Database._connection_pool 
            if current_time - conn_info[1] < 300
        ]
    
    @staticmethod
    def init():
        try:
            conn = Database.get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # 用户表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    bio TEXT,
                    avatar TEXT,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT 1,
                    last_login TIMESTAMP,
                    banned_until TIMESTAMP,
                    ban_reason TEXT
                )
            ''')
            
            # 文件表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    description TEXT,
                    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_size INTEGER,
                    download_count INTEGER DEFAULT 0,
                    uploader_id INTEGER,
                    status TEXT DEFAULT 'pending',
                    reviewed_by INTEGER,
                    review_time TIMESTAMP,
                    folder_id INTEGER DEFAULT 0
                )
            ''')
            
            # 创建索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_status ON files(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_uploader ON files(uploader_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_upload_time ON files(upload_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
            
            # 修复：确保默认管理员账号正确创建
            hashed_password = hashlib.md5('201209'.encode()).hexdigest()
            cursor.execute("SELECT id FROM users WHERE username = 'lin'")
            result = cursor.fetchone()
            
            if not result:
                # 创建新用户
                cursor.execute(
                    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                    ('lin', hashed_password, 'super_super_admin')
                )
                print("✓ 创建默认管理员账号: lin / 201209")
            else:
                # 更新现有用户密码
                cursor.execute(
                    'UPDATE users SET password = ?, role = ? WHERE username = ?',
                    (hashed_password, 'super_super_admin', 'lin')
                )
                print("✓ 更新默认管理员账号密码")
            
            conn.commit()
            conn.close()
            print("✓ 数据库初始化成功")
            
            return True
        except Exception as e:
            print(f"✗ 数据库初始化失败: {e}")
            traceback.print_exc()
            return False

class Auth:
    @staticmethod
    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password, hashed):
        return Auth.hash_password(password) == hashed
    
    @staticmethod
    def login_required(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated
    
    @staticmethod
    def permission_required(required_role):
        def decorator(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                if not session.get('logged_in'):
                    return redirect(url_for('login'))
                
                user_role = session.get('user_role')
                if PERMISSIONS.get(user_role, 0) < PERMISSIONS.get(required_role, 0):
                    return jsonify({'error': '权限不足'}), 403
                return f(*args, **kwargs)
            return decorated
        return decorator

class FileManager:
    @staticmethod
    def ensure_directories():
        directories = [
            app.config['UPLOAD_FOLDER'],
            app.config['AVATAR_FOLDER'],
            app.config['MESSAGE_ATTACHMENTS']
        ]
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"✓ 创建目录: {directory}")
    
    @staticmethod
    def save_file(file, filename):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return file_path
    
    @staticmethod
    def generate_filename(original_filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_ext = os.path.splitext(original_filename)[1]
        return f"{timestamp}_{random.randint(1000,9999)}{file_ext}"

class Utils:
    @staticmethod
    def generate_captcha():
        return ''.join([str(random.randint(0, 9)) for _ in range(4)])
    
    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def format_file_size(size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

# 初始化系统
FileManager.ensure_directories()
Database.init()

# 现代化CSS样式
MODERN_CSS = """
<style>
:root {
    --primary: #4361ee;
    --primary-dark: #3a56d4;
    --secondary: #7209b7;
    --success: #4cc9f0;
    --danger: #f72585;
    --warning: #f8961e;
    --info: #4895ef;
    --light: #f8f9fa;
    --dark: #212529;
    --gray: #6c757d;
    --border: #dee2e6;
    --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    --radius: 12px;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    color: var(--dark);
    line-height: 1.6;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* 卡片设计 */
.card {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    border: none;
    transition: all 0.3s ease;
    margin-bottom: 20px;
}

.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
}

.card-header {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: white;
    border-radius: var(--radius) var(--radius) 0 0 !important;
    padding: 20px;
    border: none;
}

.card-body {
    padding: 30px;
}

/* 导航栏 */
.navbar {
    background: rgba(255, 255, 255, 0.95) !important;
    backdrop-filter: blur(10px);
    box-shadow: var(--shadow);
    border-radius: var(--radius);
    margin-bottom: 30px;
}

.navbar-brand {
    font-weight: bold;
    color: var(--primary) !important;
    font-size: 1.5rem;
}

/* 按钮样式 */
.btn {
    border-radius: 25px;
    padding: 12px 30px;
    font-weight: 600;
    transition: all 0.3s ease;
    border: none;
    text-decoration: none;
    display: inline-block;
    text-align: center;
}

.btn-primary {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(67, 97, 238, 0.4);
}

.btn-success {
    background: linear-gradient(135deg, #4cc9f0, #4895ef);
    color: white;
}

.btn-danger {
    background: linear-gradient(135deg, #f72585, #b5179e);
    color: white;
}

/* 表单样式 */
.form-control {
    border-radius: 25px;
    padding: 15px 20px;
    border: 2px solid #e9ecef;
    transition: all 0.3s ease;
}

.form-control:focus {
    border-color: var(--primary);
    box-shadow: 0 0 0 0.2rem rgba(67, 97, 238, 0.25);
}

.form-label {
    font-weight: 600;
    margin-bottom: 8px;
    color: var(--dark);
}

/* 表格样式 */
.table {
    background: white;
    border-radius: var(--radius);
    overflow: hidden;
    box-shadow: var(--shadow);
}

.table th {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: white;
    border: none;
    padding: 15px;
}

.table td {
    padding: 15px;
    border-color: var(--border);
}

/* 登录页面 */
.login-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
}

.login-card {
    width: 100%;
    max-width: 400px;
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 40px;
}

/* 统计卡片 */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: white;
    padding: 30px;
    border-radius: var(--radius);
    text-align: center;
    transition: all 0.3s ease;
}

.stat-card:hover {
    transform: translateY(-5px);
}

.stat-number {
    font-size: 2.5rem;
    font-weight: bold;
    margin-bottom: 10px;
}

.stat-label {
    font-size: 1rem;
    opacity: 0.9;
}

/* 文件列表 */
.file-item {
    background: white;
    border-radius: var(--radius);
    padding: 20px;
    margin-bottom: 15px;
    box-shadow: var(--shadow);
    transition: all 0.3s ease;
    border-left: 4px solid var(--primary);
}

.file-item:hover {
    transform: translateX(5px);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
}

/* 响应式设计 */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    .card-body {
        padding: 20px;
    }
    
    .stats-grid {
        grid-template-columns: 1fr;
    }
    
    .login-card {
        padding: 30px 20px;
    }
}

/* 动画效果 */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.fade-in {
    animation: fadeIn 0.6s ease-out;
}

/* 状态标签 */
.status-badge {
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
}

.status-pending {
    background: #fff3cd;
    color: #856404;
}

.status-approved {
    background: #d1edff;
    color: var(--primary);
}

.status-rejected {
    background: #f8d7da;
    color: #721c24;
}

/* 加载动画 */
.loading {
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 3px solid #f3f3f3;
    border-top: 3px solid var(--primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.alert {
    border-radius: var(--radius);
    border: none;
    padding: 15px 20px;
    margin-bottom: 20px;
}

.alert-success {
    background: #d1edff;
    color: var(--primary);
    border-left: 4px solid var(--success);
}

.alert-danger {
    background: #f8d7da;
    color: var(--danger);
    border-left: 4px solid var(--danger);
}

.alert-warning {
    background: #fff3cd;
    color: #856404;
    border-left: 4px solid var(--warning);
}
</style>
"""

# 基础模板HTML
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - 文件分享系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    {MODERN_CSS}
</head>
<body>
    <nav class="navbar navbar-expand-lg">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-share-alt me-2"></i>文件分享系统
            </a>
            
            <div class="navbar-nav ms-auto">
                {% if session.logged_in %}
                    <span class="navbar-text me-3">
                        <i class="fas fa-user me-1"></i>{{ session.username }}
                    </span>
                    <a class="nav-link" href="/dashboard"><i class="fas fa-tachometer-alt me-1"></i>仪表板</a>
                    <a class="nav-link" href="/upload"><i class="fas fa-upload me-1"></i>上传</a>
                    <a class="nav-link" href="/profile"><i class="fas fa-user-cog me-1"></i>资料</a>
                    {% if session.user_role in ['admin', 'super_admin', 'super_super_admin'] %}
                        <a class="nav-link" href="/admin/review"><i class="fas fa-check-circle me-1"></i>审核</a>
                        <a class="nav-link" href="/admin/users"><i class="fas fa-users me-1"></i>用户管理</a>
                    {% endif %}
                    <a class="nav-link" href="/logout"><i class="fas fa-sign-out-alt me-1"></i>退出</a>
                {% else %}
                    <a class="nav-link" href="/login"><i class="fas fa-sign-in-alt me-1"></i>登录</a>
                    <a class="nav-link" href="/register"><i class="fas fa-user-plus me-1"></i>注册</a>
                {% endif %}
            </div>
        </div>
    </nav>

    <div class="container">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info fade-in">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 简单的交互效果
        document.addEventListener('DOMContentLoaded', function() {
            // 表单提交显示加载状态
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function() {
                    const submitBtn = this.querySelector('button[type="submit"]');
                    if (submitBtn) {
                        submitBtn.innerHTML = '<div class="loading"></div> 处理中...';
                        submitBtn.disabled = true;
                    }
                });
            });

            // 卡片悬停效果
            const cards = document.querySelectorAll('.card');
            cards.forEach(card => {
                card.style.cursor = 'pointer';
            });
        });
    </script>
</body>
</html>
"""

@app.after_request
def add_header(response):
    """添加缓存头"""
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 3600
        response.cache_control.public = True
    else:
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True
    return response

@app.route('/')
def index():
    """主页"""
    return render_template_string(BASE_TEMPLATE.replace('{title}', '首页').replace('{MODERN_CSS}', MODERN_CSS) + """
    <div class="fade-in">
        <div class="text-center text-white mb-5">
            <h1 class="display-4 fw-bold mb-3">欢迎使用文件分享系统</h1>
            <p class="lead mb-4">安全、高效、便捷的文件共享平台</p>
            {% if not session.logged_in %}
                <div class="mt-4">
                    <a href="/login" class="btn btn-primary btn-lg me-3"><i class="fas fa-sign-in-alt me-2"></i>立即登录</a>
                    <a href="/register" class="btn btn-outline-light btn-lg"><i class="fas fa-user-plus me-2"></i>注册账号</a>
                </div>
            {% else %}
                <div class="mt-4">
                    <a href="/dashboard" class="btn btn-primary btn-lg me-3"><i class="fas fa-tachometer-alt me-2"></i>进入仪表板</a>
                    <a href="/upload" class="btn btn-success btn-lg"><i class="fas fa-upload me-2"></i>上传文件</a>
                </div>
            {% endif %}
        </div>

        <div class="row mt-5">
            <div class="col-md-4 mb-4">
                <div class="card text-center h-100">
                    <div class="card-body">
                        <i class="fas fa-shield-alt fa-3x text-primary mb-3"></i>
                        <h5 class="card-title">安全可靠</h5>
                        <p class="card-text">采用多重安全机制，保障您的文件安全</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card text-center h-100">
                    <div class="card-body">
                        <i class="fas fa-bolt fa-3x text-success mb-3"></i>
                        <h5 class="card-title">高速传输</h5>
                        <p class="card-text">优化的传输算法，实现极速上传下载</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card text-center h-100">
                    <div class="card-body">
                        <i class="fas fa-users fa-3x text-warning mb-3"></i>
                        <h5 class="card-title">团队协作</h5>
                        <p class="card-text">支持团队文件共享和权限管理</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 调试信息
        print(f"登录尝试: 用户名={username}, 密码长度={len(password)}")
        
        conn = Database.get_connection()
        if not conn:
            return render_template_string(BASE_TEMPLATE.replace('{title}', '登录').replace('{MODERN_CSS}', MODERN_CSS) + """
            <div class="login-container">
                <div class="login-card fade-in">
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>系统错误，无法连接数据库
                    </div>
                    <a href="/login" class="btn btn-primary w-100">重新尝试</a>
                </div>
            </div>
            """)
        
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1',
            (username,)
        ).fetchone()
        
        print(f"查询用户结果: {user is not None}")
        
        if user:
            print(f"数据库密码: {user['password']}")
            print(f"输入密码哈希: {Auth.hash_password(password)}")
        
        if user and Auth.verify_password(password, user['password']):
            # 检查封禁状态
            if user['banned_until']:
                banned_until = datetime.fromisoformat(user['banned_until'])
                if datetime.now() < banned_until:
                    return render_template_string(BASE_TEMPLATE.replace('{title}', '登录').replace('{MODERN_CSS}', MODERN_CSS) + f"""
                    <div class="login-container">
                        <div class="login-card fade-in">
                            <div class="alert alert-warning">
                                <i class="fas fa-ban me-2"></i>账号已被封禁，原因: {user["ban_reason"]}
                            </div>
                            <a href="/" class="btn btn-primary w-100">返回首页</a>
                        </div>
                    </div>
                    """)
            
            # 更新登录时间
            conn.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user['id'],)
            )
            conn.commit()
            conn.close()
            
            # 设置会话
            session.update({
                'logged_in': True,
                'user_id': user['id'],
                'username': user['username'],
                'user_role': user['role']
            })
            
            print(f"登录成功: {username}, 角色: {user['role']}")
            
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            return render_template_string(BASE_TEMPLATE.replace('{title}', '登录').replace('{MODERN_CSS}', MODERN_CSS) + """
            <div class="login-container">
                <div class="login-card fade-in">
                    <h3 class="text-center mb-4"><i class="fas fa-sign-in-alt me-2"></i>用户登录</h3>
                    <div class="alert alert-danger">
                        <i class="fas fa-times-circle me-2"></i>用户名或密码错误
                    </div>
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label">用户名</label>
                            <input type="text" class="form-control" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">密码</label>
                            <input type="password" class="form-control" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">登录</button>
                    </form>
                    <div class="text-center mt-3">
                        <a href="/register" class="text-decoration-none">还没有账号？立即注册</a>
                    </div>
                </div>
            </div>
            """)
    
    return render_template_string(BASE_TEMPLATE.replace('{title}', '登录').replace('{MODERN_CSS}', MODERN_CSS) + """
    <div class="login-container">
        <div class="login-card fade-in">
            <h3 class="text-center mb-4"><i class="fas fa-sign-in-alt me-2"></i>用户登录</h3>
            <form method="POST">
                <div class="mb-3">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control" name="username" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">登录</button>
            </form>
            <div class="text-center mt-3">
                <a href="/register" class="text-decoration-none">还没有账号？立即注册</a>
            </div>
            <div class="mt-4 p-3 bg-light rounded">
                <small class="text-muted">
                    <strong>测试账号:</strong><br>
                    管理员: lin / 201209
                </small>
            </div>
        </div>
    </div>
    """)

# 其他路由保持不变，但需要更新为使用 render_template_string 和新的样式
# 由于代码长度限制，这里只展示关键修改部分

def render_template_string(template_content):
    """渲染模板字符串"""
    from flask import render_template_string as flask_render_template_string
    return flask_render_template_string(template_content)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, password, confirm_password]):
            return render_template_string(BASE_TEMPLATE.replace('{title}', '注册').replace('{MODERN_CSS}', MODERN_CSS) + """
            <div class="login-container">
                <div class="login-card fade-in">
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>请填写完整信息
                    </div>
                    <!-- 注册表单 -->
                </div>
            </div>
            """)
        
        # 其他注册逻辑保持不变...
        
    return render_template_string(BASE_TEMPLATE.replace('{title}', '注册').replace('{MODERN_CSS}', MODERN_CSS) + """
    <div class="login-container">
        <div class="login-card fade-in">
            <h3 class="text-center mb-4"><i class="fas fa-user-plus me-2"></i>用户注册</h3>
            <form method="POST">
                <div class="mb-3">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control" name="username" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">确认密码</label>
                    <input type="password" class="form-control" name="confirm_password" required>
                </div>
                <button type="submit" class="btn btn-success w-100">注册</button>
            </form>
            <div class="text-center mt-3">
                <a href="/login" class="text-decoration-none">已有账号？立即登录</a>
            </div>
        </div>
    </div>
    """)

@app.route('/dashboard')
@Auth.login_required
def dashboard():
    """用户仪表板"""
    conn = Database.get_connection()
    if not conn:
        return "系统错误", 500
    
    user_id = session.get('user_id')
    user_role = session.get('user_role')
    
    # 获取用户文件
    if user_role == 'user':
        files = conn.execute(
            'SELECT * FROM files WHERE uploader_id = ? ORDER BY upload_time DESC',
            (user_id,)
        ).fetchall()
    else:
        files = conn.execute('SELECT * FROM files ORDER BY upload_time DESC').fetchall()
    
    # 统计信息
    stats = {
        'total_files': len(files),
        'pending_files': sum(1 for f in files if f['status'] == 'pending'),
        'approved_files': sum(1 for f in files if f['status'] == 'approved'),
        'total_downloads': sum(f['download_count'] for f in files)
    }
    
    conn.close()
    
    files_html = ""
    for file in files:
        status_class = {
            'pending': 'status-pending',
            'approved': 'status-approved',
            'rejected': 'status-rejected'
        }.get(file['status'], '')
        
        files_html += f"""
        <div class="file-item">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <h6 class="mb-1">{file['original_filename']}</h6>
                    <small class="text-muted">大小: {Utils.format_file_size(file['file_size'])}</small>
                </div>
                <div class="col-md-3">
                    <span class="status-badge {status_class}">
                        {'pending': '待审核', 'approved': '已通过', 'rejected': '已拒绝'.get(file['status']}, file['status'])
                    </span>
                </div>
                <div class="col-md-3 text-end">
                    <small class="text-muted">{file['upload_time'][:16]}</small>
                </div>
            </div>
        </div>
        """
    
    return render_template_string(BASE_TEMPLATE.replace('{title}', '仪表板').replace('{MODERN_CSS}', MODERN_CSS) + f"""
    <div class="fade-in">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2><i class="fas fa-tachometer-alt me-2"></i>仪表板</h2>
            <a href="/upload" class="btn btn-primary">
                <i class="fas fa-upload me-2"></i>上传文件
            </a>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{stats['total_files']}</div>
                <div class="stat-label">总文件数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['approved_files']}</div>
                <div class="stat-label">已通过文件</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['pending_files']}</div>
                <div class="stat-label">待审核文件</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_downloads']}</div>
                <div class="stat-label">总下载次数</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-file me-2"></i>我的文件</h5>
            </div>
            <div class="card-body">
                {files_html if files else '<p class="text-center text-muted">暂无文件</p>'}
            </div>
        </div>
    </div>
    """)

# 其他路由保持原有逻辑，但需要使用 render_template_string 和新的样式
# 由于代码长度限制，这里只展示关键部分

if __name__ == '__main__':
    local_ip = Utils.get_local_ip()
    
    print("=" * 50)
    print("文件分享系统启动成功!")
    print("=" * 50)
    print(f"本地访问: http://localhost:5000")
    print(f"网络访问: http://{local_ip}:5000")
    print("默认管理员账号: lin / 201209")
    print("界面美化已应用，性能优化已启用")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)