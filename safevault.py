"""SafeVault: dependency-free educational WSGI security demonstration.

Run: python safevault.py
Admin accounts are not self-registerable; provision using admin CLI command.
"""
import argparse
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from http import HTTPStatus
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_MIN = 12
MAX_BODY = 4096


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat()


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 310000)
    return f'pbkdf2_sha256$310000${salt.hex()}${digest.hex()}'


def verify_password(password, stored):
    try:
        method, rounds, salt, expected = stored.split('$')
        if method != 'pbkdf2_sha256' or int(rounds) < 310000:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


class SafeVault:
    def __init__(self, db_path='safevault.db'):
        self.db_path = str(db_path)
        self.init_db()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db_path)
        try:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            with db:
                yield db
        finally:
            db.close()

    def init_db(self):
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN (\'user\',\'admin\')))')
            db.execute('CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, content TEXT NOT NULL)')

    def create_user(self, username, password, role='user', privileged=False):
        if not isinstance(username, str) or not USER_RE.fullmatch(username):
            raise ValueError('username must be 3-32 letters, digits, underscores, hyphens or dots')
        if not isinstance(password, str) or len(password) < PASSWORD_MIN or len(password) > 256:
            raise ValueError('password must contain 12-256 characters')
        if role not in ('user', 'admin') or (role == 'admin' and not privileged):
            raise ValueError('invalid or unauthorized role')
        with self.connect() as db:
            db.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)', (username, hash_password(password), role))

    def authenticate(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        with self.connect() as db:
            user = db.execute('SELECT id, password_hash FROM users WHERE username=?', (username,)).fetchone()
            if not user or not verify_password(password, user['password_hash']):
                return None
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            db.execute('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)', (token_hash, user['id'], iso(now() + timedelta(hours=1))))
            return token

    def user_for_token(self, token):
        if not token or len(token) > 256:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as db:
            return db.execute('SELECT users.id,username,role FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?', (digest, iso(now()))).fetchone()

    def revoke_token(self, token):
        with self.connect() as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))

    def response(self, start_response, status, payload, content_type='application/json; charset=utf-8'):
        content = (json.dumps(payload) if content_type.startswith('application/json') else payload).encode('utf-8')
        start_response(f'{status} {HTTPStatus(status).phrase}', [('Content-Type', content_type), ('Content-Length', str(len(content))), ('X-Content-Type-Options','nosniff'), ('X-Frame-Options','DENY'), ('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'"), ('Cache-Control','no-store'), ('Referrer-Policy','no-referrer')])
        return [content]

    def __call__(self, environ, start_response):
        method, path = environ['REQUEST_METHOD'], environ.get('PATH_INFO', '/')
        if environ.get('CONTENT_LENGTH', ''):
            try:
                size = int(environ['CONTENT_LENGTH'])
            except ValueError:
                return self.response(start_response, 400, {'error':'invalid request size'})
            if size < 0 or size > MAX_BODY:
                return self.response(start_response, 413, {'error':'request too large'})
        else:
            size = 0
        data = {}
        if method == 'POST':
            if environ.get('CONTENT_TYPE', '').split(';')[0] != 'application/json':
                return self.response(start_response, 415, {'error':'JSON required'})
            try:
                data = json.loads(environ['wsgi.input'].read(size))
                if not isinstance(data, dict):
                    raise ValueError()
            except (ValueError, UnicodeDecodeError):
                return self.response(start_response, 400, {'error':'invalid JSON'})
        header = environ.get('HTTP_AUTHORIZATION', '')
        token = header[7:] if header.startswith('Bearer ') else ''
        user = self.user_for_token(token)
        if method == 'POST' and path == '/register':
            if set(data) != {'username', 'password'}:
                return self.response(start_response, 400, {'error':'only username and password allowed'})
            try:
                self.create_user(data['username'], data['password'])
                return self.response(start_response, 201, {'message':'created'})
            except sqlite3.IntegrityError:
                return self.response(start_response, 409, {'error':'username unavailable'})
            except ValueError as exc:
                return self.response(start_response, 400, {'error':str(exc)})
        if method == 'POST' and path == '/login':
            if set(data) != {'username', 'password'}:
                return self.response(start_response, 400, {'error':'invalid credentials'})
            token_new = self.authenticate(data['username'], data['password'])
            return self.response(start_response, 200 if token_new else 401, {'token':token_new, 'token_type':'Bearer', 'expires_in':3600} if token_new else {'error':'invalid credentials'})
        if method == 'GET' and path == '/preview':
            query = parse_qs(environ.get('QUERY_STRING', ''), keep_blank_values=True)
            value = query.get('text', [''])[0]
            if len(value) > 200:
                return self.response(start_response, 400, {'error':'text too long'})
            safe = '<!doctype html><html><body><p>' + html.escape(value, quote=True) + '</p></body></html>'
            return self.response(start_response, 200, safe, 'text/html; charset=utf-8')
        if not user:
            return self.response(start_response, 401, {'error':'authentication required'})
        if method == 'POST' and path == '/logout':
            self.revoke_token(token)
            return self.response(start_response, 200, {'message':'logged out'})
        if method == 'GET' and path == '/me':
            return self.response(start_response, 200, {'username':user['username'], 'role':user['role']})
        if method == 'GET' and path == '/admin/users':
            if user['role'] != 'admin':
                return self.response(start_response, 403, {'error':'forbidden'})
            with self.connect() as db:
                records = [dict(r) for r in db.execute('SELECT id,username,role FROM users ORDER BY id').fetchall()]
            return self.response(start_response, 200, {'users':records})
        if method == 'POST' and path == '/secrets':
            title, content = data.get('title'), data.get('content')
            if set(data) != {'title', 'content'} or not isinstance(title, str) or not 1 <= len(title) <= 100 or not isinstance(content, str) or not 1 <= len(content) <= 2000:
                return self.response(start_response, 400, {'error':'invalid secret fields'})
            with self.connect() as db:
                cursor = db.execute('INSERT INTO secrets(owner_id,title,content) VALUES(?,?,?)', (user['id'],title,content))
                secret_id = cursor.lastrowid
            return self.response(start_response, 201, {'id':secret_id})
        if method == 'GET' and path == '/secrets':
            with self.connect() as db:
                records = [dict(r) for r in db.execute('SELECT id,title,content FROM secrets WHERE owner_id=? ORDER BY id', (user['id'],)).fetchall()]
            return self.response(start_response, 200, {'secrets':records})
        return self.response(start_response, 404, {'error':'not found'})


def main():
    parser = argparse.ArgumentParser(description='SafeVault security example')
    parser.add_argument('--db', default=os.environ.get('SAFEVAULT_DB','safevault.db'))
    sub = parser.add_subparsers(dest='command')
    admin = sub.add_parser('create-admin', help='provision admin locally, not via public API')
    admin.add_argument('username')
    args = parser.parse_args()
    app = SafeVault(args.db)
    if args.command == 'create-admin':
        import getpass
        app.create_user(args.username, getpass.getpass('Admin password (12+ characters): '), role='admin', privileged=True)
        print('Admin created')
    else:
        print('Development-only HTTP server on http://127.0.0.1:8000; use HTTPS reverse proxy for deployment')
        with make_server('127.0.0.1', 8000, app) as server:
            server.serve_forever()


if __name__ == '__main__':
    main()
