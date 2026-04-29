"""
Alexander AI Solutions — AI-Powered Tech Dropshipping Platform
Built by Echo (KiloClaw) for Jay Alexander
"""

import os, json, sqlite3, secrets, functools, time, hashlib
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g)
import requests
import bcrypt as _bcrypt

app = Flask(__name__)

# ── Secret key (persistent across redeploys) ──────────────────────────────────
def _get_secret_key():
    env_key = os.environ.get('SECRET_KEY')
    if env_key: return env_key
    data_dir = os.environ.get('DATA_DIR', '/data')
    key_file = os.path.join(data_dir, 'secret_key')
    try:
        os.makedirs(data_dir, exist_ok=True)
        if os.path.exists(key_file):
            with open(key_file) as f:
                k = f.read().strip()
            if k: return k
        k = secrets.token_hex(32)
        with open(key_file, 'w') as f: f.write(k)
        return k
    except Exception:
        return secrets.token_hex(32)

app.secret_key = _get_secret_key()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# ── Data directory ────────────────────────────────────────────────────────────
_data_pref = os.environ.get('DATA_DIR', '/data')
try:
    os.makedirs(_data_pref, exist_ok=True)
    _t = os.path.join(_data_pref, '.write_test')
    open(_t, 'w').close(); os.remove(_t)
    DATA_DIR = _data_pref
except Exception:
    DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(DATA_DIR, exist_ok=True)

DB_FILE       = os.path.join(DATA_DIR, 'aais.db')
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')

ADMIN_USER  = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS  = os.environ.get('ADMIN_PASSWORD', 'admin1234')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'jay@alexanderaisolutions.com')
APP_NAME    = 'Alexander AI Solutions'

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_FILE)
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'admin',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cj_pid TEXT UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        cost REAL,
        image_url TEXT,
        category TEXT,
        stock INTEGER DEFAULT 0,
        supplier_url TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_num TEXT UNIQUE NOT NULL,
        customer_name TEXT NOT NULL,
        customer_email TEXT NOT NULL,
        customer_address TEXT NOT NULL,
        items TEXT NOT NULL,
        subtotal REAL NOT NULL,
        total REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        stripe_session_id TEXT,
        cj_order_id TEXT,
        tracking_number TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS app_config (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    # Create admin user
    pw = _bcrypt.hashpw(ADMIN_PASS.encode(), _bcrypt.gensalt()).decode()
    db.execute('INSERT OR IGNORE INTO users (username,password,email,role) VALUES (?,?,?,?)',
               (ADMIN_USER, pw, ADMIN_EMAIL, 'admin'))
    db.execute('UPDATE users SET password=?,email=? WHERE username=?',
               (pw, ADMIN_EMAIL, ADMIN_USER))
    db.commit()
    db.close()

init_db()

# ── Config helpers ─────────────────────────────────────────────────────────────
def get_config(key, default=''):
    db = get_db()
    row = db.execute('SELECT value FROM app_config WHERE key=?', (key,)).fetchone()
    return row['value'] if row else default

def set_config(key, value):
    db = get_db()
    db.execute('INSERT OR REPLACE INTO app_config (key,value) VALUES (?,?)', (key, str(value)))
    db.commit()

def load_settings():
    """Load persistent settings from JSON (survives redeploys)."""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE) as f:
                return json.load(f)
    except Exception: pass
    return {}

def save_settings(data):
    """Save settings to persistent JSON file."""
    try:
        existing = load_settings()
        existing.update(data)
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        print(f'Warning: could not save settings: {e}')

def get_setting(key, default=''):
    """Get a setting — checks JSON file first, then DB, then env."""
    val = load_settings().get(key)
    if val: return val
    val = get_config(key)
    if val: return val
    # Check env var (e.g. cj_api_key -> CJ_API_KEY)
    env_val = os.environ.get(key.upper(), os.environ.get(key, default))
    return env_val

# ── CSRF ──────────────────────────────────────────────────────────────────────
def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf():
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'): return True
    if request.path.startswith('/api/'): return True
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    return token and token == session.get('csrf_token')

app.jinja_env.globals['csrf_token'] = get_csrf_token
app.jinja_env.globals['get_setting'] = get_setting
app.jinja_env.filters['from_json'] = lambda s: json.loads(s) if s else []

from urllib.parse import quote as _url_quote
app.jinja_env.filters['urlencode'] = lambda s: _url_quote(str(s), safe='')

@app.before_request
def csrf_protect():
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        if not request.path.startswith('/api/'):
            if not validate_csrf():
                from flask import abort
                abort(403)

# ── Auth ──────────────────────────────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def decorated(*a, **kw):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*a, **kw)
    return decorated

@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if 'Content-Security-Policy' not in response.headers:
        response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;"
    return response

# ── CJ Dropshipping API ───────────────────────────────────────────────────────
CJ_API_BASE = 'https://developers.cjdropshipping.com/api2.0/v1'

def cj_get_token():
    """Get or refresh CJ API access token."""
    api_key = get_setting('cj_api_key')
    if not api_key: return None

    # Check cached token
    s = load_settings()
    cached_token   = s.get('cj_access_token')
    token_expires  = s.get('cj_token_expires', 0)
    if cached_token and time.time() < float(token_expires) - 60:
        return cached_token

    # Get fresh token
    try:
        resp = requests.post(f'{CJ_API_BASE}/authentication/getAccessToken',
                             json={'apiKey': api_key}, timeout=15)
        data = resp.json()
        if data.get('result'):
            token   = data['data']['accessToken']
            expires = time.time() + (data['data'].get('expiresIn', 3600))
            save_settings({'cj_access_token': token, 'cj_token_expires': str(expires)})
            return token
    except Exception as e:
        print(f'CJ token error: {e}')
    return None

def cj_request(method, endpoint, **kwargs):
    """Make an authenticated CJ API request."""
    token = cj_get_token()
    if not token:
        return {'result': False, 'message': 'CJ API key not configured'}
    headers = {'CJ-Access-Token': token, 'Content-Type': 'application/json'}
    try:
        resp = getattr(requests, method.lower())(
            f'{CJ_API_BASE}/{endpoint}',
            headers=headers, timeout=30, **kwargs
        )
        return resp.json()
    except Exception as e:
        return {'result': False, 'message': str(e)}

def cj_search_products(keyword, page=1, page_size=20):
    """Search CJ product catalog."""
    return cj_request('get', 'product/list', params={
        'productNameEn': keyword,
        'pageNum': page,
        'pageSize': page_size
    })

def cj_get_product(cj_pid):
    """Get full product details from CJ."""
    return cj_request('get', f'product/query', params={'pid': cj_pid})

def cj_create_order(order_data):
    """Submit order to CJ for fulfillment."""
    return cj_request('post', 'shopping/order/createOrderV2', json=order_data)

def cj_get_order_status(cj_order_id):
    """Check CJ order status + tracking."""
    return cj_request('get', 'shopping/order/getOrderDetail',
                      params={'orderId': cj_order_id})

# ── Routes — Public ───────────────────────────────────────────────────────────
@app.route('/')
def index():
    db = get_db()
    featured = db.execute(
        'SELECT * FROM products WHERE active=1 ORDER BY created_at DESC LIMIT 12'
    ).fetchall()
    categories = db.execute(
        'SELECT DISTINCT category FROM products WHERE active=1 AND category IS NOT NULL'
    ).fetchall()
    return render_template('index.html', products=featured, categories=categories)

@app.route('/shop')
def shop():
    db = get_db()
    category = request.args.get('category', '')
    search   = request.args.get('q', '')
    query    = 'SELECT * FROM products WHERE active=1'
    params   = []
    if category:
        query += ' AND category=?'; params.append(category)
    if search:
        query += ' AND (name LIKE ? OR description LIKE ?)';
        params += [f'%{search}%', f'%{search}%']
    query += ' ORDER BY created_at DESC'
    products   = db.execute(query, params).fetchall()
    categories = db.execute('SELECT DISTINCT category FROM products WHERE active=1 AND category IS NOT NULL').fetchall()
    return render_template('shop.html', products=products, categories=categories,
                           current_category=category, search=search)

@app.route('/product/<int:pid>')
def product_detail(pid):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id=? AND active=1', (pid,)).fetchone()
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('shop'))
    related = db.execute(
        'SELECT * FROM products WHERE active=1 AND category=? AND id!=? LIMIT 4',
        (product['category'], pid)
    ).fetchall()
    return render_template('product.html', product=product, related=related)

# ── Cart ──────────────────────────────────────────────────────────────────────
@app.route('/cart')
def cart():
    cart_items = _get_cart()
    subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
    return render_template('cart.html', cart=cart_items, subtotal=subtotal)

@app.route('/api/cart/add', methods=['POST'])
def cart_add():
    data = request.get_json() or {}
    pid  = data.get('product_id')
    qty  = int(data.get('quantity', 1))
    if not pid:
        return jsonify({'error': 'No product id'}), 400
    db      = get_db()
    product = db.execute('SELECT * FROM products WHERE id=? AND active=1', (pid,)).fetchone()
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    sid = _get_session_id()
    existing = db.execute('SELECT * FROM cart WHERE session_id=? AND product_id=?', (sid, pid)).fetchone()
    if existing:
        db.execute('UPDATE cart SET quantity=quantity+? WHERE session_id=? AND product_id=?',
                   (qty, sid, pid))
    else:
        db.execute('INSERT INTO cart (session_id, product_id, quantity) VALUES (?,?,?)',
                   (sid, pid, qty))
    db.commit()
    count = db.execute('SELECT SUM(quantity) as total FROM cart WHERE session_id=?', (sid,)).fetchone()
    return jsonify({'success': True, 'cart_count': count['total'] or 0})

@app.route('/api/cart/remove', methods=['POST'])
def cart_remove():
    data = request.get_json() or {}
    pid  = data.get('product_id')
    sid  = _get_session_id()
    get_db().execute('DELETE FROM cart WHERE session_id=? AND product_id=?', (sid, pid))
    get_db().commit()
    return jsonify({'success': True})

@app.route('/api/cart/update', methods=['POST'])
def cart_update():
    data = request.get_json() or {}
    pid  = data.get('product_id')
    qty  = int(data.get('quantity', 1))
    sid  = _get_session_id()
    if qty <= 0:
        get_db().execute('DELETE FROM cart WHERE session_id=? AND product_id=?', (sid, pid))
    else:
        get_db().execute('UPDATE cart SET quantity=? WHERE session_id=? AND product_id=?',
                         (qty, sid, pid))
    get_db().commit()
    return jsonify({'success': True})

@app.route('/api/cart/count')
def cart_count():
    sid = _get_session_id()
    row = get_db().execute('SELECT SUM(quantity) as total FROM cart WHERE session_id=?', (sid,)).fetchone()
    return jsonify({'count': row['total'] or 0})

def _get_session_id():
    if 'cart_session' not in session:
        session['cart_session'] = secrets.token_hex(16)
    return session['cart_session']

def _get_cart():
    sid = _get_session_id()
    db  = get_db()
    rows = db.execute('''
        SELECT c.product_id, c.quantity, p.name, p.price, p.image_url, p.cj_pid
        FROM cart c JOIN products p ON c.product_id=p.id
        WHERE c.session_id=? AND p.active=1
    ''', (sid,)).fetchall()
    return [dict(r) for r in rows]

# ── Checkout ──────────────────────────────────────────────────────────────────
@app.route('/checkout')
def checkout():
    cart_items = _get_cart()
    if not cart_items:
        return redirect(url_for('cart'))
    subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
    shipping = 0 if subtotal >= 50 else 4.99
    total    = subtotal + shipping
    return render_template('checkout.html', cart=cart_items,
                           subtotal=subtotal, shipping=shipping, total=total)

@app.route('/checkout/place', methods=['POST'])
def place_order():
    cart_items = _get_cart()
    if not cart_items:
        return redirect(url_for('cart'))

    name    = request.form.get('name','').strip()
    email   = request.form.get('email','').strip()
    address = request.form.get('address','').strip()
    city    = request.form.get('city','').strip()
    state   = request.form.get('state','').strip()
    zip_c   = request.form.get('zip','').strip()
    country = request.form.get('country','US').strip()

    if not all([name, email, address, city, state, zip_c]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('checkout'))

    full_address = f'{address}, {city}, {state} {zip_c}, {country}'
    subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
    shipping = 0 if subtotal >= 50 else 4.99
    total    = subtotal + shipping
    order_num = 'AAIS-' + secrets.token_hex(4).upper()

    db = get_db()
    db.execute('''INSERT INTO orders
        (order_num, customer_name, customer_email, customer_address, items, subtotal, total, status)
        VALUES (?,?,?,?,?,?,?,?)''',
        (order_num, name, email, full_address, json.dumps(cart_items),
         subtotal, total, 'pending'))
    db.commit()

    # Clear cart
    sid = _get_session_id()
    db.execute('DELETE FROM cart WHERE session_id=?', (sid,))
    db.commit()

    # Auto-fulfill via CJ if API key is set
    order_id = db.execute('SELECT id FROM orders WHERE order_num=?', (order_num,)).fetchone()['id']
    _auto_fulfill_order(order_id)

    return redirect(url_for('order_confirmation', order_num=order_num))

@app.route('/order/<order_num>')
def order_confirmation(order_num):
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE order_num=?', (order_num,)).fetchone()
    if not order:
        return redirect(url_for('index'))
    return render_template('order_confirmation.html', order=order,
                           items=json.loads(order['items']))

def _auto_fulfill_order(order_id):
    """Attempt to auto-fulfill via CJ Dropshipping."""
    if not get_setting('cj_api_key'):
        return  # No key configured yet

    db    = get_db()
    order = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    if not order: return

    items = json.loads(order['items'])
    # Build CJ order payload
    products = []
    for item in items:
        if item.get('cj_pid'):
            products.append({
                'vid':      item['cj_pid'],
                'quantity': item['quantity']
            })

    if not products:
        db.execute("UPDATE orders SET notes='No CJ PIDs — manual fulfillment needed' WHERE id=?",
                   (order_id,))
        db.commit()
        return

    addr_parts = order['customer_address'].split(',')
    cj_payload = {
        'orderNumber':  order['order_num'],
        'shippingZip':  addr_parts[-2].strip().split(' ')[-1] if len(addr_parts) >= 2 else '',
        'shippingCountry': 'US',
        'shippingAddress': addr_parts[0].strip() if addr_parts else order['customer_address'],
        'shippingCity': addr_parts[1].strip() if len(addr_parts) > 1 else '',
        'shippingProvince': addr_parts[2].strip().split(' ')[0] if len(addr_parts) > 2 else '',
        'shippingCustomerName': order['customer_name'],
        'shippingPhone': '0000000000',
        'products': products
    }

    result = cj_create_order(cj_payload)
    if result.get('result'):
        cj_order_id = result['data'].get('orderId', '')
        db.execute("UPDATE orders SET cj_order_id=?, status='processing' WHERE id=?",
                   (cj_order_id, order_id))
    else:
        db.execute("UPDATE orders SET notes=?, status='needs_review' WHERE id=?",
                   (f"CJ error: {result.get('message','')}", order_id))
    db.commit()

# ── Admin AI Assistant ───────────────────────────────────────────────────────
@app.route('/admin/ai')
@login_required
def admin_ai():
    db = get_db()
    stats = {
        'products':  db.execute('SELECT COUNT(*) as c FROM products WHERE active=1').fetchone()['c'],
        'orders':    db.execute('SELECT COUNT(*) as c FROM orders').fetchone()['c'],
        'revenue':   db.execute('SELECT SUM(total) as s FROM orders WHERE status!="cancelled"').fetchone()['s'] or 0,
        'pending':   db.execute('SELECT COUNT(*) as c FROM orders WHERE status="pending"').fetchone()['c'],
    }
    ai_configured = bool(get_setting('openrouter_key'))
    quick_actions = [
        ('💡 What products should I add?', 'What are the top 5 trending tech products I should add to my dropshipping store right now? Focus on keyboards, peripherals, and desk accessories under $60.'),
        ('📝 Write product description', 'Write me a compelling product description for a mechanical keyboard. Make it 2-3 sentences, professional, with keywords buyers search for.'),
        ('📈 Marketing email', 'Write me a short promotional email to send to customers. We have a sale on tech gear this week. Include subject line and body. Under 150 words.'),
        ('💰 Pricing advice', 'What markup percentage should I use for keyboard and tech accessories from CJ Dropshipping? Consider shipping times and competition.'),
        ('🔍 Find hot niches', 'What are 3 specific tech product niches that are trending right now with good profit margins for dropshipping? Include estimated margin.'),
        ('📊 Analyze my business', f'I have {stats["products"]} products, {stats["orders"]} orders, and ${stats["revenue"]:.2f} in revenue with {stats["pending"]} pending orders. Give me 3 specific things I should do right now to grow.'),
        ('🚀 Growth strategy', 'Give me a 30-day action plan to grow my tech dropshipping store. Be specific and prioritize by impact.'),
        ('🛒 Reduce cart abandonment', 'What are the top 3 reasons customers abandon carts on tech dropshipping stores, and how do I fix each one?'),
    ]
    return render_template('admin/ai.html', stats=stats, ai_configured=ai_configured, quick_actions=quick_actions)

# ── Admin Routes ──────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        db   = get_db()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and _bcrypt.checkpw(password.encode(), user['password'].encode()):
            session.clear()
            session['logged_in'] = True
            session['username']  = username
            session['role']      = user['role']
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    db = get_db()
    stats = {
        'products':  db.execute('SELECT COUNT(*) as c FROM products WHERE active=1').fetchone()['c'],
        'orders':    db.execute('SELECT COUNT(*) as c FROM orders').fetchone()['c'],
        'revenue':   db.execute('SELECT SUM(total) as s FROM orders WHERE status!="cancelled"').fetchone()['s'] or 0,
        'pending':   db.execute('SELECT COUNT(*) as c FROM orders WHERE status="pending"').fetchone()['c'],
        'processing':db.execute('SELECT COUNT(*) as c FROM orders WHERE status="processing"').fetchone()['c'],
    }
    recent_orders = db.execute(
        'SELECT * FROM orders ORDER BY created_at DESC LIMIT 10'
    ).fetchall()
    cj_configured = bool(get_setting('cj_api_key'))
    return render_template('admin/dashboard.html', stats=stats,
                           recent_orders=recent_orders, cj_configured=cj_configured)

@app.route('/admin/products')
@login_required
def admin_products():
    db       = get_db()
    products = db.execute('SELECT * FROM products ORDER BY created_at DESC').fetchall()
    return render_template('admin/products.html', products=products)

@app.route('/admin/products/add', methods=['GET','POST'])
@login_required
def admin_add_product():
    if request.method == 'POST':
        db = get_db()
        db.execute('''INSERT INTO products
            (cj_pid, name, description, price, cost, image_url, category, stock)
            VALUES (?,?,?,?,?,?,?,?)''', (
            request.form.get('cj_pid','').strip(),
            request.form.get('name','').strip(),
            request.form.get('description','').strip(),
            float(request.form.get('price', 0)),
            float(request.form.get('cost', 0) or 0),
            request.form.get('image_url','').strip(),
            request.form.get('category','').strip(),
            int(request.form.get('stock', 99))
        ))
        db.commit()
        flash('Product added!', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin/add_product.html')

@app.route('/admin/products/edit/<int:pid>', methods=['GET','POST'])
@login_required
def admin_edit_product(pid):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('admin_products'))
    if request.method == 'POST':
        db.execute('''UPDATE products SET
            cj_pid=?, name=?, description=?, price=?, cost=?,
            image_url=?, category=?, stock=?, active=?
            WHERE id=?''', (
            request.form.get('cj_pid','').strip(),
            request.form.get('name','').strip(),
            request.form.get('description','').strip(),
            float(request.form.get('price', 0)),
            float(request.form.get('cost', 0) or 0),
            request.form.get('image_url','').strip(),
            request.form.get('category','').strip(),
            int(request.form.get('stock', 0)),
            1 if request.form.get('active') else 0,
            pid
        ))
        db.commit()
        flash('Product updated!', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin/edit_product.html', product=product)

@app.route('/admin/products/delete/<int:pid>', methods=['POST'])
@login_required
def admin_delete_product(pid):
    get_db().execute('UPDATE products SET active=0 WHERE id=?', (pid,))
    get_db().commit()
    flash('Product removed.', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/orders')
@login_required
def admin_orders():
    db     = get_db()
    status = request.args.get('status', '')
    if status:
        orders = db.execute('SELECT * FROM orders WHERE status=? ORDER BY created_at DESC', (status,)).fetchall()
    else:
        orders = db.execute('SELECT * FROM orders ORDER BY created_at DESC').fetchall()
    return render_template('admin/orders.html', orders=orders, current_status=status)

@app.route('/admin/orders/<int:oid>')
@login_required
def admin_order_detail(oid):
    db    = get_db()
    order = db.execute('SELECT * FROM orders WHERE id=?', (oid,)).fetchone()
    if not order:
        flash('Order not found.', 'error')
        return redirect(url_for('admin_orders'))
    return render_template('admin/order_detail.html', order=order,
                           items=json.loads(order['items']))

@app.route('/admin/orders/<int:oid>/fulfill', methods=['POST'])
@login_required
def admin_fulfill_order(oid):
    """Manually trigger CJ fulfillment for an order."""
    _auto_fulfill_order(oid)
    db    = get_db()
    order = db.execute('SELECT * FROM orders WHERE id=?', (oid,)).fetchone()
    flash(f'Fulfillment attempted. Status: {order["status"]}', 'info')
    return redirect(url_for('admin_order_detail', oid=oid))

@app.route('/admin/orders/<int:oid>/update-status', methods=['POST'])
@login_required
def admin_update_order_status(oid):
    new_status = request.form.get('status','')
    tracking   = request.form.get('tracking_number','').strip()
    db = get_db()
    if tracking:
        db.execute('UPDATE orders SET status=?, tracking_number=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                   (new_status, tracking, oid))
    else:
        db.execute('UPDATE orders SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                   (new_status, oid))
    db.commit()
    flash('Order updated.', 'success')
    return redirect(url_for('admin_order_detail', oid=oid))

# ── Settings ──────────────────────────────────────────────────────────────────
@app.route('/admin/settings', methods=['GET','POST'])
@login_required
def admin_settings():
    if request.method == 'POST':
        updates = {}

        cj_api_key = request.form.get('cj_api_key','').strip()
        if cj_api_key:
            updates['cj_api_key'] = cj_api_key
            set_config('cj_api_key', cj_api_key)
            # Clear cached token so it refreshes with new key
            updates['cj_access_token'] = ''
            updates['cj_token_expires'] = '0'

        stripe_secret = request.form.get('stripe_secret_key','').strip()
        if stripe_secret:
            updates['stripe_secret_key'] = stripe_secret
            set_config('stripe_secret_key', stripe_secret)

        stripe_pub = request.form.get('stripe_publishable_key','').strip()
        if stripe_pub:
            updates['stripe_publishable_key'] = stripe_pub
            set_config('stripe_publishable_key', stripe_pub)

        openrouter_key = request.form.get('openrouter_key','').strip()
        if openrouter_key:
            updates['openrouter_key'] = openrouter_key
            set_config('openrouter_key', openrouter_key)

        store_name = request.form.get('store_name','').strip()
        if store_name:
            updates['store_name'] = store_name
            set_config('store_name', store_name)

        support_email = request.form.get('support_email','').strip()
        if support_email:
            updates['support_email'] = support_email
            set_config('support_email', support_email)

        if updates:
            save_settings(updates)

        flash('Settings saved!', 'success')
        return redirect(url_for('admin_settings'))

    s = load_settings()

    # Build masked previews
    def mask(val):
        if not val: return ''
        if len(val) > 8: return val[:8] + '...' + val[-4:]
        return '••••••••'

    return render_template('admin/settings.html',
        cj_key_set     = bool(get_setting('cj_api_key')),
        cj_key_preview = mask(get_setting('cj_api_key')),
        stripe_secret_set = bool(get_setting('stripe_secret_key')),
        stripe_pub_set    = bool(get_setting('stripe_publishable_key')),
        openrouter_set = bool(get_setting('openrouter_key')),
        store_name     = get_setting('store_name', APP_NAME),
        support_email  = get_setting('support_email', ADMIN_EMAIL),
    )

# ── CJ Product Search API (admin) ─────────────────────────────────────────────
@app.route('/api/cj/search')
@login_required
def api_cj_search():
    keyword   = request.args.get('q','').strip()
    page      = int(request.args.get('page', 1))
    if not keyword:
        return jsonify({'error': 'No search term'}), 400
    if not get_setting('cj_api_key'):
        return jsonify({'error': 'CJ API key not configured. Go to Settings to add it.'}), 400
    result = cj_search_products(keyword, page=page)
    return jsonify(result)

@app.route('/api/cj/import', methods=['POST'])
@login_required
def api_cj_import():
    """Import a product from CJ search results into the store."""
    data = request.get_json() or {}
    db   = get_db()

    # Calculate sell price with markup
    cost   = float(data.get('sellPrice', data.get('cost', 0)) or 0)
    markup = float(get_setting('markup_percent', '50'))
    price  = round(cost * (1 + markup / 100), 2)
    price  = max(price, cost + 1)  # Always at least $1 profit

    existing = db.execute('SELECT id FROM products WHERE cj_pid=?', (data.get('pid',''),)).fetchone()
    if existing:
        return jsonify({'error': 'Product already imported', 'product_id': existing['id']}), 409

    db.execute('''INSERT INTO products (cj_pid, name, description, price, cost, image_url, category, stock)
                  VALUES (?,?,?,?,?,?,?,?)''', (
        data.get('pid',''),
        data.get('productNameEn', data.get('name', 'Unknown')),
        data.get('description',''),
        price,
        cost,
        data.get('productImage', data.get('image_url','')),
        data.get('categoryName', data.get('category', 'Tech')),
        99
    ))
    db.commit()
    pid = db.execute('SELECT last_insert_rowid() as id').fetchone()['id']
    return jsonify({'success': True, 'product_id': pid, 'sell_price': price})

@app.route('/admin/import', methods=['GET'])
@login_required
def admin_import():
    """Product import page — search CJ and import with one click."""
    markup = get_setting('markup_percent', '50')
    cj_configured = bool(get_setting('cj_api_key'))
    return render_template('admin/import.html', markup=markup, cj_configured=cj_configured)

# ── AI Chat API ──────────────────────────────────────────────────────────────────
@app.route('/api/bot/chat', methods=['POST'])
@login_required
def api_bot_chat():
    """AI business assistant — powered by OpenRouter."""
    data    = request.get_json() or {}
    message = data.get('message', '').strip()
    history = data.get('history', [])

    if not message:
        return jsonify({'error': 'No message provided'}), 400

    api_key = get_setting('openrouter_key')
    if not api_key:
        return jsonify({'reply': '⚠️ OpenRouter key not configured. Go to Settings → OpenRouter AI and add your key to enable the AI assistant.'})  

    # Build store context for system prompt
    db = get_db()
    total_products = db.execute('SELECT COUNT(*) as c FROM products WHERE active=1').fetchone()['c']
    total_orders   = db.execute('SELECT COUNT(*) as c FROM orders').fetchone()['c']
    revenue        = db.execute('SELECT SUM(total) as s FROM orders WHERE status!="cancelled"').fetchone()['s'] or 0
    pending        = db.execute('SELECT COUNT(*) as c FROM orders WHERE status="pending"').fetchone()['c']
    store_name     = get_setting('store_name', 'Alexander AI Solutions')
    categories     = db.execute('SELECT DISTINCT category FROM products WHERE active=1 AND category IS NOT NULL').fetchall()
    cat_list       = ', '.join([r['category'] for r in categories]) if categories else 'mixed tech'

    system_prompt = f"""You are an AI business assistant for {store_name}, a tech dropshipping store.

Current store stats:
- Products: {total_products} active
- Total orders: {total_orders}
- Revenue: ${revenue:.2f}
- Pending orders: {pending}
- Categories: {cat_list}

Your role: help the owner grow the business. Give specific, actionable advice.
Focus on: product sourcing, pricing strategy, marketing, operations, customer service.
Be concise, direct, and practical. No fluff. Use bullet points when listing multiple items."""

    # Build messages
    messages = [{'role': 'system', 'content': system_prompt}]
    for h in history[-10:]:  # last 10 messages for context
        if h.get('role') in ('user', 'assistant') and h.get('content'):
            messages.append({'role': h['role'], 'content': h['content']})
    messages.append({'role': 'user', 'content': message})

    try:
        resp = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'HTTP-Referer': request.host_url,
                'X-Title': store_name,
            },
            json={
                'model': get_setting('ai_model', 'google/gemini-2.0-flash-001'),
                'messages': messages,
                'max_tokens': 1024,
                'temperature': 0.7,
            },
            timeout=30
        )
        result = resp.json()
        if result.get('choices'):
            reply = result['choices'][0]['message']['content']
            return jsonify({'reply': reply})
        elif result.get('error'):
            return jsonify({'reply': f"AI error: {result['error'].get('message', 'Unknown error')}"})
        else:
            return jsonify({'reply': 'No response from AI. Check your OpenRouter key.'})
    except requests.exceptions.Timeout:
        return jsonify({'reply': 'AI request timed out. Try again.'}), 200
    except Exception as e:
        app.logger.error(f'AI chat error: {e}')
        return jsonify({'reply': f'Error connecting to AI: {str(e)}'}), 200


# ── Order tracking status update from CJ ──────────────────────────────────────
@app.route('/api/orders/sync-tracking', methods=['POST'])
@login_required
def sync_tracking():
    """Check CJ for tracking updates on all processing orders."""
    db = get_db()
    orders = db.execute(
        "SELECT * FROM orders WHERE status='processing' AND cj_order_id IS NOT NULL AND cj_order_id!='' AND tracking_number IS NULL"
    ).fetchall()
    updated = 0
    for order in orders:
        result = cj_get_order_status(order['cj_order_id'])
        if result.get('result'):
            tracking = result.get('data', {}).get('trackingNumber','')
            if tracking:
                db.execute("UPDATE orders SET tracking_number=?, status='shipped', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                           (tracking, order['id']))
                updated += 1
    db.commit()
    return jsonify({'success': True, 'updated': updated})

# ── Health check ──────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    try:
        get_db().execute('SELECT 1').fetchone()
        db_ok = True
    except Exception:
        db_ok = False
    return json.dumps({
        'status': 'ok' if db_ok else 'degraded',
        'db': 'ok' if db_ok else 'error',
        'cj_configured': bool(get_setting('cj_api_key')),
        'app': APP_NAME
    }), 200 if db_ok else 503, {'Content-Type': 'application/json'}

@app.route('/healthz')
def healthz(): return 'ok'

# ── Context ───────────────────────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    sid = session.get('cart_session')
    cart_count = 0
    if sid:
        try:
            row = get_db().execute('SELECT SUM(quantity) as t FROM cart WHERE session_id=?', (sid,)).fetchone()
            cart_count = row['t'] or 0
        except Exception: pass
    return {
        'app_name':  get_setting('store_name', APP_NAME),
        'cart_count': cart_count,
        'now': datetime.utcnow(),
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
