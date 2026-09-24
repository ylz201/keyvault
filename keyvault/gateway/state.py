"""Private SQLite control plane: administrator methods are NOT RPC tools."""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from .protocol import GatewayError, canonical, identifier, validate_operation

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
 id TEXT PRIMARY KEY, workspace TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
 expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS operations (
 id TEXT PRIMARY KEY, workspace TEXT NOT NULL, config TEXT NOT NULL,
 digest TEXT NOT NULL, credential_revision TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS grants (
 id TEXT PRIMARY KEY, client TEXT NOT NULL REFERENCES clients(id),
 operation TEXT NOT NULL REFERENCES operations(id), digest TEXT NOT NULL,
 expires REAL NOT NULL, max_uses INTEGER NOT NULL, uses INTEGER NOT NULL DEFAULT 0,
 revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS requests (
 client TEXT NOT NULL, request_id TEXT NOT NULL, grant_id TEXT NOT NULL,
 operation TEXT NOT NULL, state TEXT NOT NULL, result TEXT,
 created REAL NOT NULL, PRIMARY KEY(client, request_id));
CREATE TABLE IF NOT EXISTS audit (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, client TEXT,
 request_id TEXT, event TEXT NOT NULL);
"""

def private_file(path: Path, *, create=False):
    """Do not silently accept symlinks, foreign ownership or permissive state."""
    if os.name != "posix":
        raise GatewayError("UNSUPPORTED_PLATFORM")
    path = Path(path)
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise GatewayError("UNSAFE_STATE_PERMISSIONS")
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise GatewayError("UNSAFE_STATE_PERMISSIONS")

class State:
    def __init__(self, path: Path):
        self.path = Path(path)
        private_file(self.path, create=True)
        with self.transaction() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def transaction(self):
        private_file(self.path)
        db = sqlite3.connect(str(self.path), timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def event(db, event, client=None, request=None):
        db.execute("INSERT INTO audit(at,client,request_id,event) VALUES(?,?,?,?)", (time.time(), client, request, event))

    def create_client(self, client, workspace, ttl=86400):
        identifier(client); identifier(workspace)
        if type(ttl) is not int or not 1 <= ttl <= 365 * 86400:
            raise GatewayError("INVALID_INPUT")
        token = secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute("INSERT INTO clients(id,workspace,token_hash,expires) VALUES(?,?,?,?)",
                       (client, workspace, hashlib.sha256(token.encode()).hexdigest(), time.time() + ttl))
            self.event(db, "CLIENT_CREATED", client)
        return token

    def register_operation(self, config, provider):
        validate_operation(config)
        secret = provider.resolve(config["credential"])
        from .provider import validate_secret
        validate_secret(secret.value)
        # Detect key changes; existing grants never silently follow a rotated value.
        text = canonical(config)
        digest = hashlib.sha256((text + "\0" + secret.revision).encode()).hexdigest()
        with self.transaction() as db:
            db.execute("INSERT INTO operations(id,workspace,config,digest,credential_revision) VALUES(?,?,?,?,?)",
                       (config["id"], config["workspace"], text, digest, secret.revision))
            self.event(db, "OPERATION_REGISTERED")
        return digest

    def grant(self, grant, client, operation, ttl=3600, max_uses=10):
        for value in (grant, client, operation):
            identifier(value)
        if type(ttl) is not int or not 1 <= ttl <= 30 * 86400 or type(max_uses) is not int or not 1 <= max_uses <= 100000:
            raise GatewayError("INVALID_INPUT")
        with self.transaction() as db:
            c = db.execute("SELECT * FROM clients WHERE id=?", (client,)).fetchone()
            op = db.execute("SELECT * FROM operations WHERE id=?", (operation,)).fetchone()
            if not c or not op or c["workspace"] != op["workspace"] or c["revoked"] or not op["enabled"] or c["expires"] <= time.time():
                raise GatewayError("GRANT_DENIED")
            db.execute("INSERT INTO grants(id,client,operation,digest,expires,max_uses) VALUES(?,?,?,?,?,?)",
                       (grant, client, operation, op["digest"], min(time.time() + ttl, c["expires"]), max_uses))
            self.event(db, "GRANT_CREATED", client)

    def revoke(self, kind, ref):
        identifier(ref)
        tables = {"client": ("clients", "revoked", 1), "grant": ("grants", "revoked", 1), "operation": ("operations", "enabled", 0)}
        if kind not in tables:
            raise GatewayError("INVALID_INPUT")
        table, column, value = tables[kind]
        with self.transaction() as db:
            changed = db.execute(f"UPDATE {table} SET {column}=? WHERE id=?", (value, ref)).rowcount
            if not changed:
                raise GatewayError("NOT_FOUND")
            self.event(db, kind.upper() + "_REVOKED")

    @staticmethod
    def authenticate(db, token):
        if not isinstance(token, str) or len(token) != 43:
            raise GatewayError("UNAUTHENTICATED")
        row = db.execute("SELECT * FROM clients WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not row or row["revoked"] or row["expires"] <= time.time():
            raise GatewayError("UNAUTHENTICATED")
        return row

    @staticmethod
    def authorized(db, client, grant):
        row = db.execute("""SELECT g.*, o.config, o.credential_revision, o.enabled,
           o.digest AS operation_digest, o.workspace FROM grants g
           JOIN operations o ON o.id=g.operation WHERE g.id=? AND g.client=?""", (grant, client["id"])).fetchone()
        if not row or row["workspace"] != client["workspace"] or row["revoked"] or not row["enabled"] or row["expires"] <= time.time() or row["digest"] != row["operation_digest"]:
            raise GatewayError("FORBIDDEN")
        return row
