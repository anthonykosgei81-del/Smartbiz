#!/usr/bin/env python3
"""SmartBiz v2 backend. Standard library only: no installs needed. Run: python3 server.py"""
import json, os, re, sqlite3, secrets, hashlib, hmac, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("SMARTBIZ_DATA", os.path.join(HERE, "data"))  # one database file per business
SESSION_DAYS = 7
PAYS = ("Cash", "M-Pesa", "Credit")

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS branches(id TEXT PRIMARY KEY, name TEXT NOT NULL, loc TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  salt TEXT NOT NULL, pin_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('owner','manager','cashier')),
  branch_id TEXT REFERENCES branches(id));
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, exp REAL NOT NULL);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, name TEXT NOT NULL, sku TEXT DEFAULT '',
  price REAL NOT NULL CHECK(price>=0), cost REAL NOT NULL CHECK(cost>=0), min INTEGER NOT NULL DEFAULT 5);
CREATE TABLE IF NOT EXISTS stock(branch_id TEXT REFERENCES branches(id), product_id TEXT REFERENCES products(id) ON DELETE CASCADE,
  qty INTEGER NOT NULL DEFAULT 0 CHECK(qty>=0), PRIMARY KEY(branch_id, product_id));
CREATE TABLE IF NOT EXISTS customers(id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT DEFAULT '', owed REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS suppliers(id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT DEFAULT '', item TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS sales(id TEXT PRIMARY KEY, no TEXT, branch_id TEXT NOT NULL REFERENCES branches(id), d TEXT NOT NULL, t TEXT NOT NULL,
  total REAL NOT NULL, pay TEXT NOT NULL, customer_id TEXT, by TEXT);
CREATE TABLE IF NOT EXISTS sale_items(sale_id TEXT NOT NULL REFERENCES sales(id) ON DELETE CASCADE, product_id TEXT, name TEXT, qty INTEGER, price REAL, cost REAL);
CREATE TABLE IF NOT EXISTS expenses(id TEXT PRIMARY KEY, branch_id TEXT NOT NULL REFERENCES branches(id), d TEXT NOT NULL, note TEXT, amt REAL NOT NULL CHECK(amt>=0));
CREATE INDEX IF NOT EXISTS ix_sales_d ON sales(d); CREATE INDEX IF NOT EXISTS ix_exp_d ON expenses(d);
"""

class Err(Exception):
    def __init__(s, msg, code=400): s.msg, s.code = msg, code

def dbpath(code):
    if not re.fullmatch(r"[a-z0-9]{6}", str(code or "")): raise Err("Unknown business code.", 404)
    return os.path.join(DATA, code + ".db")

def conn(code, create=False):
    p = dbpath(code)
    if not create and not os.path.exists(p): raise Err("Unknown business code.", 404)
    c = sqlite3.connect(p, isolation_level=None, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA journal_mode=WAL")
    return c

def uid(): return secrets.token_hex(4)
def hp(pin, salt): return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200_000).hex()
def mkuser(db, name, pin, role, branch=None):
    salt = secrets.token_hex(16)
    db.execute("INSERT INTO users VALUES(?,?,?,?,?,?)", (uid(), name, salt, hp(pin, salt), role, branch or None))

def init(): os.makedirs(DATA, exist_ok=True)

def text(v, n=120, req=True):
    v = str(v or "").strip()[:n]
    if req and not v: raise Err("Please fill in all required fields.")
    return v
def num(v, req=True):
    try: x = float(v)
    except (TypeError, ValueError):
        if req: raise Err("Enter a valid number.")
        return 0.0
    if x < 0 or x != x or x > 1e9: raise Err("Number is out of range.")
    return x

RANK = {"cashier": 0, "manager": 1, "owner": 2}
ROUTES = []
def R(method, pat, role=0, public=False):
    def deco(f): ROUTES.append((method, re.compile("^" + pat + "$"), role, public, f)); return f
    return deco

def sale_rows(db, where="", args=()):
    sales = [dict(r) for r in db.execute(f"SELECT id,no,branch_id,d,t,total,pay,customer_id,by FROM sales {where} ORDER BY rowid DESC LIMIT 2000", args)]
    ids = {s["id"]: s for s in sales}
    for s in sales: s.update(branch=s.pop("branch_id"), cust=s.pop("customer_id") or "", items=[])
    for r in db.execute("SELECT * FROM sale_items"):
        if r["sale_id"] in ids: ids[r["sale_id"]]["items"].append({"pid": r["product_id"], "name": r["name"], "qty": r["qty"], "price": r["price"], "cost": r["cost"]})
    return sales[::-1]

def state(db, u):
    b = u["branch_id"]
    bf, ba = ("WHERE branch_id=?", (b,)) if b else ("", ())
    boss = u["role"] != "cashier"
    st = {"biz": db.execute("SELECT v FROM settings WHERE k='biz'").fetchone()[0],
          "me": {"id": u["id"], "name": u["name"], "role": u["role"], "branch": b or ""},
          "branches": [dict(r) for r in db.execute("SELECT id,name,loc FROM branches" + (" WHERE id=?" if b else ""), ba[:1])],
          "products": [{**dict(r), "cost": r["cost"] if boss else 0} for r in db.execute("SELECT id,name,sku,price,cost,min FROM products ORDER BY name")],
          "stock": {}, "sales": sale_rows(db, bf, ba),
          "expenses": [{**dict(r), "branch": r["branch_id"]} for r in db.execute(f"SELECT id,branch_id,d,note,amt FROM expenses {bf}", ba)],
          "customers": [dict(r) for r in db.execute("SELECT id,name,phone,owed FROM customers ORDER BY name")],
          "suppliers": [dict(r) for r in db.execute("SELECT id,name,phone,item FROM suppliers ORDER BY name")],
          "users": []}
    for r in db.execute(f"SELECT branch_id,product_id,qty FROM stock {bf}", ba): st["stock"].setdefault(r[0], {})[r[1]] = r[2]
    if not boss:
        for s in st["sales"]:
            for i in s["items"]: i["cost"] = 0
    if u["role"] == "owner":
        st["users"] = [{"id": r["id"], "name": r["name"], "role": r["role"], "branch": r["branch_id"] or ""} for r in db.execute("SELECT * FROM users")]
    return st

FAILS = {}
@R("POST", "/api/login", public=True)
def login(db, u, m, b):
    name = text(b.get("name"), 60)
    n, t = FAILS.get((b.get("code", "") + name).lower(), (0, 0))
    if n >= 5 and time.time() - t < 300: raise Err("Too many attempts. Wait 5 minutes.", 429)
    r = db.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    if not r or not hmac.compare_digest(hp(str(b.get("pin", "")), r["salt"]), r["pin_hash"]):
        FAILS[(b.get("code", "") + name).lower()] = (n + 1, time.time()); raise Err("Wrong name or PIN.", 401)
    FAILS.pop((b.get("code", "") + name).lower(), None)
    tok = b["code"] + "." + secrets.token_urlsafe(32)
    db.execute("DELETE FROM sessions WHERE exp<?", (time.time(),))
    db.execute("INSERT INTO sessions VALUES(?,?,?)", (tok, r["id"], time.time() + SESSION_DAYS * 86400))
    return {"token": tok}

SIGNUPS = {}
@R("POST", "/api/signup", public=True)
def signup(db, u, m, b):
    ip, now = b.get("_ip", ""), time.time()
    hits = [t for t in SIGNUPS.get(ip, []) if now - t < 3600]
    if len(hits) >= 10: raise Err("Too many sign-ups from this address. Try again later.", 429)
    biz, owner, pin = text(b.get("biz"), 80), text(b.get("name"), 60), text(b.get("pin"), 20)
    if len(pin) < 4: raise Err("PIN must be at least 4 characters.")
    for _ in range(30):
        code = "".join(secrets.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(6))
        if not os.path.exists(dbpath(code)): break
    db = conn(code, create=True)
    try:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO branches VALUES('b1',?,'')", (text(b.get("branch"), 60, False) or "Main branch",))
        db.execute("INSERT INTO settings VALUES('biz',?)", (biz,))
        mkuser(db, owner, pin, "owner")
        tok = code + "." + secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions VALUES(?,?,?)", (tok, db.execute("SELECT id FROM users").fetchone()[0], now + SESSION_DAYS * 86400))
    finally: db.close()
    SIGNUPS[ip] = hits + [now]
    return {"token": tok, "code": code}

@R("GET", "/api/state")
def get_state(db, u, m, b): return state(db, u)

@R("POST", "/api/me/pin")
def my_pin(db, u, m, b):
    new = text(b.get("new"), 20)
    if len(new) < 4: raise Err("PIN must be at least 4 characters.")
    if hp(str(b.get("old", "")), u["salt"]) != u["pin_hash"]: raise Err("Current PIN is wrong.", 403)
    s = secrets.token_hex(16); db.execute("UPDATE users SET salt=?,pin_hash=? WHERE id=?", (s, hp(new, s), u["id"])); return {}

def prod_fields(b): return (text(b.get("name")), text(b.get("sku"), 60, False), num(b.get("price")), num(b.get("cost")), int(num(b.get("min"), False)))
@R("POST", "/api/products", 1)
def add_prod(db, u, m, b):
    f = prod_fields(b); i = uid()
    db.execute("INSERT INTO products VALUES(?,?,?,?,?,?)", (i, *f))
    db.execute("INSERT INTO stock SELECT id,?,0 FROM branches", (i,)); return {}
@R("PUT", "/api/products/(\\w+)", 1)
def edit_prod(db, u, m, b): db.execute("UPDATE products SET name=?,sku=?,price=?,cost=?,min=? WHERE id=?", (*prod_fields(b), m[1])); return {}
@R("DELETE", "/api/products/(\\w+)", 1)
def del_prod(db, u, m, b): db.execute("DELETE FROM products WHERE id=?", (m[1],)); return {}

@R("POST", "/api/restock", 1)
def restock(db, u, m, b):
    db.execute("INSERT OR IGNORE INTO stock VALUES(?,?,0)", (b.get("branch"), b.get("product")))
    db.execute("UPDATE stock SET qty=MAX(0,qty+?) WHERE branch_id=? AND product_id=?", (int(float(b.get("qty", 0))), b.get("branch"), b.get("product"))); return {}

@R("POST", "/api/sales")
def make_sale(db, u, m, b):
    br = u["branch_id"] or b.get("branch")
    if not db.execute("SELECT 1 FROM branches WHERE id=?", (br,)).fetchone(): raise Err("Choose a branch.")
    pay, cust = b.get("pay"), b.get("cust") or None
    if pay not in PAYS: raise Err("Invalid payment method.")
    if pay == "Credit" and not cust: raise Err("Choose a customer for a credit sale.")
    want = {}
    for i in b.get("items", []): want[i["pid"]] = want.get(i["pid"], 0) + int(i["qty"])
    if not want or any(q < 1 for q in want.values()): raise Err("The cart is empty.")
    db.execute("BEGIN IMMEDIATE")
    try:
        items, total = [], 0.0
        for pid, q in want.items():
            p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
            have = db.execute("SELECT qty FROM stock WHERE branch_id=? AND product_id=?", (br, pid)).fetchone()
            if not p: raise Err("A product no longer exists.")
            if not have or have[0] < q: raise Err(f"Not enough stock for {p['name']}.")
            db.execute("UPDATE stock SET qty=qty-? WHERE branch_id=? AND product_id=?", (q, br, pid))
            items.append((pid, p["name"], q, p["price"], p["cost"])); total += q * p["price"]
        if cust:
            if db.execute("UPDATE customers SET owed=owed+? WHERE id=?", (total if pay == "Credit" else 0, cust)).rowcount == 0: raise Err("Customer not found.")
        sid, n = uid(), db.execute("SELECT COUNT(*) FROM sales").fetchone()[0] + 1
        lt = time.localtime()
        db.execute("INSERT INTO sales VALUES(?,?,?,?,?,?,?,?,?)", (sid, f"R{n:04d}", br, time.strftime("%Y-%m-%d", lt), time.strftime("%H:%M", lt), total, pay, cust, u["name"]))
        db.executemany("INSERT INTO sale_items VALUES(?,?,?,?,?,?)", [(sid, *i) for i in items])
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK"); raise
    return {"sale": sale_rows(db, "WHERE id=?", (sid,))[0]}

@R("POST", "/api/expenses", 1)
def add_exp(db, u, m, b):
    br = u["branch_id"] or b.get("branch")
    db.execute("INSERT INTO expenses VALUES(?,?,?,?,?)", (uid(), br, time.strftime("%Y-%m-%d"), text(b.get("note")), num(b.get("amt")))); return {}
@R("DELETE", "/api/expenses/(\\w+)", 1)
def del_exp(db, u, m, b): db.execute("DELETE FROM expenses WHERE id=?", (m[1],)); return {}

@R("POST", "/api/customers")
def add_cust(db, u, m, b): db.execute("INSERT INTO customers VALUES(?,?,?,0)", (uid(), text(b.get("name")), text(b.get("phone"), 30, False))); return {}
@R("DELETE", "/api/customers/(\\w+)", 1)
def del_cust(db, u, m, b): db.execute("DELETE FROM customers WHERE id=?", (m[1],)); return {}
@R("POST", "/api/customers/(\\w+)/pay")
def pay_debt(db, u, m, b): db.execute("UPDATE customers SET owed=MAX(0,owed-?) WHERE id=?", (num(b.get("amt")), m[1])); return {}

@R("POST", "/api/suppliers", 1)
def add_sup(db, u, m, b): db.execute("INSERT INTO suppliers VALUES(?,?,?,?)", (uid(), text(b.get("name")), text(b.get("phone"), 30, False), text(b.get("item"), 80, False))); return {}
@R("DELETE", "/api/suppliers/(\\w+)", 1)
def del_sup(db, u, m, b): db.execute("DELETE FROM suppliers WHERE id=?", (m[1],)); return {}

@R("POST", "/api/business", 2)
def biz(db, u, m, b): db.execute("INSERT OR REPLACE INTO settings VALUES('biz',?)", (text(b.get("name")),)); return {}
@R("POST", "/api/branches", 2)
def add_branch(db, u, m, b):
    i = uid(); db.execute("INSERT INTO branches VALUES(?,?,?)", (i, text(b.get("name")), text(b.get("loc"), 80, False)))
    db.execute("INSERT INTO stock SELECT ?,id,0 FROM products", (i,)); return {}
@R("POST", "/api/users", 2)
def add_user(db, u, m, b):
    pin = text(b.get("pin"), 20)
    if len(pin) < 4: raise Err("PIN must be at least 4 characters.")
    if b.get("role") not in RANK: raise Err("Invalid role.")
    try: mkuser(db, text(b.get("name"), 60), pin, b["role"], b.get("branch"))
    except sqlite3.IntegrityError: raise Err("That name is already used.")
    return {}
@R("DELETE", "/api/users/(\\w+)", 2)
def del_user(db, u, m, b):
    if m[1] == u["id"]: raise Err("You cannot remove your own account.")
    db.execute("DELETE FROM users WHERE id=?", (m[1],)); return {}

class H(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def send(s, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        s.send_response(code); s.send_header("Content-Type", ctype); s.send_header("Content-Length", str(len(data)))
        s.send_header("X-Content-Type-Options", "nosniff"); s.send_header("Cache-Control", "no-store"); s.end_headers(); s.wfile.write(data)
    def handle_any(s, method):
        path = s.path.split("?")[0]
        if method == "GET" and path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f: return s.send(200, f.read(), "text/html; charset=utf-8")
        db = None
        try:
            for meth, rx, role, public, fn in ROUTES:
                mt = rx.match(path)
                if meth != method or not mt: continue
                n = int(s.headers.get("Content-Length") or 0)
                if n > 200_000: raise Err("Request too large.", 413)
                try: body = json.loads(s.rfile.read(n) or b"{}")
                except ValueError: raise Err("Bad request.")
                u = None
                if not public:
                    tok = s.headers.get("Authorization", "")[7:]
                    try: db = conn(tok.split(".")[0])
                    except Err: raise Err("Please sign in again.", 401)
                    u = db.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.exp>?", (tok, time.time())).fetchone()
                    if not u: raise Err("Please sign in again.", 401)
                    if RANK[u["role"]] < role: raise Err("Your account cannot do this.", 403)
                elif path == "/api/signup": body["_ip"] = (s.headers.get("X-Forwarded-For", "").split(",")[0].strip() if s.client_address[0] == "127.0.0.1" else "") or s.client_address[0]
                else: db = conn(body.get("code"))
                return s.send(200, fn(db, u, mt, body))
            raise Err("Not found.", 404)
        except Err as e: s.send(e.code, {"error": e.msg})
        except (sqlite3.Error, KeyError, TypeError, ValueError, AttributeError) as e:
            s.send(400, {"error": "Invalid request or data."})
        finally:
            if db: db.close()
    do_GET = lambda s: s.handle_any("GET")
    do_POST = lambda s: s.handle_any("POST")
    do_PUT = lambda s: s.handle_any("PUT")
    do_DELETE = lambda s: s.handle_any("DELETE")

if __name__ == "__main__":
    init()
    host, port = os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", 8000))
    print(f"SmartBiz running at http://{host}:{port}")
    ThreadingHTTPServer((host, port), H).serve_forever()
