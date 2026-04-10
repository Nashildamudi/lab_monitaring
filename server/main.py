import os
import json
import secrets
import sqlite3
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


DB_PATH = os.path.join(os.path.dirname(__file__), "labmon.db")
ADMIN_PASSWORD = os.environ.get("LABMON_ADMIN_PASSWORD", "")
BOOTSTRAP_ADMIN_USER = os.environ.get("LABMON_ADMIN_USER", "admin")
BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("LABMON_ADMIN_PASS", "admin")
ENROLLMENT_KEY = os.environ.get("LABMON_ENROLLMENT_KEY", "")


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init() -> None:
    with db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(admin_id) REFERENCES admins(id)
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id INTEGER,
                actor_name TEXT,
                action TEXT NOT NULL,
                data_json TEXT NOT NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                hostname TEXT,
                enrollment_code TEXT,
                token TEXT,
                enrolled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_seen TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                level TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data_json TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                command_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                delivered_at TEXT,
                executed_at TEXT,
                FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                ts TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )
        
        # Pre-populate blocked URLs if table is empty
        count = conn.execute("SELECT COUNT(*) FROM blocked_urls").fetchone()[0]
        if count == 0:
            default_blocked = [
                "github.com", "*.github.com",
                "chat.openai.com", "chatgpt.com",
                "facebook.com", "*.facebook.com",
                "youtube.com", "*.youtube.com",
                "instagram.com", "*.instagram.com",
                "twitter.com", "x.com", "*.twitter.com",
                "reddit.com", "*.reddit.com"
            ]
            now = utc_now_iso()
            for pattern in default_blocked:
                conn.execute(
                    "INSERT INTO blocked_urls (pattern, enabled, created_at) VALUES (?, 1, ?)",
                    (pattern, now)
                )



class AdminAddClientRequest(BaseModel):
    name: str
    hostname: Optional[str] = None


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class AdminLoginResponse(BaseModel):
    token: str
    role: str


class AdminAddClientResponse(BaseModel):
    client_id: int
    enrollment_code: str


class AdminCommandRequest(BaseModel):
    command_type: str
    payload: Dict[str, Any] = {}


class ClientEnrollRequest(BaseModel):
    enrollment_code: str
    hostname: Optional[str] = None


class ClientRegisterRequest(BaseModel):
    name: str
    hostname: Optional[str] = None


class ClientEnrollResponse(BaseModel):
    token: str
    client_id: int


class ClientHeartbeatRequest(BaseModel):
    hostname: Optional[str] = None
    processes: List[str] = []
    alerts: List[Dict[str, Any]] = []
    cpu_percent: Optional[float] = None
    ram_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    url_violations: List[str] = []


class ClientLogEvent(BaseModel):
    level: str
    event_type: str
    data: Dict[str, Any] = {}


class ClientLogsRequest(BaseModel):
    events: List[ClientLogEvent]


class WSManager:
    def __init__(self) -> None:
        self._admin_sockets: List[WebSocket] = []

    async def connect_admin(self, ws: WebSocket) -> None:
        await ws.accept()
        self._admin_sockets.append(ws)

    def disconnect_admin(self, ws: WebSocket) -> None:
        self._admin_sockets = [s for s in self._admin_sockets if s is not ws]

    async def broadcast_admin(self, message: Dict[str, Any]) -> None:
        if not self._admin_sockets:
            return
        dead: List[WebSocket] = []
        for ws in self._admin_sockets:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect_admin(ws)


app = FastAPI(title="Smart Lab Monitoring")
ws_manager = WSManager()

db_init()


def pbkdf2_hash(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return dk.hex()


def ensure_bootstrap_admin() -> None:
    with db_connect() as conn:
        row = conn.execute("SELECT id FROM admins LIMIT 1").fetchone()
        if row:
            return
        salt = secrets.token_hex(16)
        pw_hash = pbkdf2_hash(BOOTSTRAP_ADMIN_PASSWORD, salt)
        conn.execute(
            "INSERT INTO admins (username, password_salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (BOOTSTRAP_ADMIN_USER, salt, pw_hash, "admin", utc_now_iso()),
        )


def audit(actor_type: str, actor_id: Optional[int], actor_name: Optional[str], action: str, data: Dict[str, Any]) -> None:
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO audit_logs (ts, actor_type, actor_id, actor_name, action, data_json) VALUES (?, ?, ?, ?, ?, ?)",
            (utc_now_iso(), actor_type, actor_id, actor_name, action, json.dumps(data)),
        )


ensure_bootstrap_admin()


def require_admin(authorization: Optional[str]) -> sqlite3.Row:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization")

    now = utc_now_iso()
    with db_connect() as conn:
        sess = conn.execute(
            """
            SELECT s.admin_id, s.expires_at, a.username, a.role
            FROM admin_sessions s
            JOIN admins a ON a.id = s.admin_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid session")
    if str(sess["expires_at"]) <= now:
        raise HTTPException(status_code=401, detail="Session expired")
    return sess


def require_enrollment_key(x_enrollment_key: Optional[str]) -> None:
    if not ENROLLMENT_KEY:
        return
    if not x_enrollment_key or not hmac.compare_digest(x_enrollment_key, ENROLLMENT_KEY):
        raise HTTPException(status_code=401, detail="Invalid enrollment key")


@app.post("/api/auth/login", response_model=AdminLoginResponse)
async def admin_login(req: AdminLoginRequest) -> AdminLoginResponse:
    username = (req.username or "").strip()
    password = req.password or ""
    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing username/password")

    with db_connect() as conn:
        row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if not row:
            audit("admin", None, username, "login_failed", {"reason": "no_such_user"})
            raise HTTPException(status_code=401, detail="Invalid credentials")
        salt = str(row["password_salt"])
        expected = str(row["password_hash"])
        got = pbkdf2_hash(password, salt)
        if not hmac.compare_digest(got, expected):
            audit("admin", int(row["id"]), username, "login_failed", {"reason": "bad_password"})
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = secrets.token_urlsafe(32)
        created_at = utc_now_iso()
        # 12 hours session
        expires_dt = datetime.now(timezone.utc).replace(microsecond=0)
        expires_dt = datetime.fromtimestamp(expires_dt.timestamp() + 12 * 3600, tz=timezone.utc)
        expires_iso = expires_dt.isoformat()
        conn.execute(
            "INSERT INTO admin_sessions (admin_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (int(row["id"]), token, created_at, expires_iso),
        )

    audit("admin", int(row["id"]), username, "login_success", {})
    return AdminLoginResponse(token=token, role=str(row["role"]))


def require_client_token(x_client_token: Optional[str]) -> sqlite3.Row:
    if not x_client_token:
        raise HTTPException(status_code=401, detail="Missing client token")
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM clients WHERE token = ? AND enrolled = 1",
            (x_client_token,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid client token")
    return row


@app.get("/")
def root() -> FileResponse:
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.websocket("/ws/admin")
async def ws_admin(ws: WebSocket) -> None:
    await ws_manager.connect_admin(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect_admin(ws)


@app.get("/api/admin/clients")
async def admin_list_clients(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    admin = require_admin(authorization)
    with db_connect() as conn:
        clients = conn.execute(
            "SELECT id, name, hostname, enrolled, created_at, last_seen FROM clients ORDER BY id DESC"
        ).fetchall()
    audit("admin", int(admin["admin_id"]), str(admin["username"]), "clients_list", {})
    return {"clients": [dict(r) for r in clients]}


@app.post("/api/admin/clients", response_model=AdminAddClientResponse)
async def admin_add_client(
    req: AdminAddClientRequest, authorization: Optional[str] = Header(default=None)
) -> AdminAddClientResponse:
    admin = require_admin(authorization)
    enrollment_code = secrets.token_urlsafe(16)
    created_at = utc_now_iso()
    with db_connect() as conn:
        cur = conn.execute(
            "INSERT INTO clients (name, hostname, enrollment_code, enrolled, created_at) VALUES (?, ?, ?, 0, ?)",
            (req.name, req.hostname, enrollment_code, created_at),
        )
        client_id = int(cur.lastrowid)
    await ws_manager.broadcast_admin({"type": "client_added", "client": {"id": client_id}})
    audit(
        "admin",
        int(admin["admin_id"]),
        str(admin["username"]),
        "client_added",
        {"client_id": client_id, "name": req.name, "hostname": req.hostname},
    )
    return AdminAddClientResponse(client_id=client_id, enrollment_code=enrollment_code)


@app.post("/api/admin/clients/{client_id}/commands")
async def admin_send_command(
    client_id: int,
    req: AdminCommandRequest,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    admin = require_admin(authorization)
    ts = utc_now_iso()
    with db_connect() as conn:
        exists = conn.execute("SELECT id FROM clients WHERE id = ?", (client_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Client not found")
        cur = conn.execute(
            "INSERT INTO commands (client_id, ts, command_type, payload_json, status) VALUES (?, ?, ?, ?, 'queued')",
            (client_id, ts, req.command_type, json.dumps(req.payload)),
        )
        cmd_id = int(cur.lastrowid)
    await ws_manager.broadcast_admin(
        {
            "type": "command_queued",
            "command": {"id": cmd_id, "client_id": client_id, "command_type": req.command_type, "ts": ts},
        }
    )
    audit(
        "admin",
        int(admin["admin_id"]),
        str(admin["username"]),
        "command_queued",
        {"command_id": cmd_id, "client_id": client_id, "command_type": req.command_type, "payload": req.payload},
    )
    return {"command_id": cmd_id}


@app.post("/api/client/enroll", response_model=ClientEnrollResponse)
async def client_enroll(req: ClientEnrollRequest) -> ClientEnrollResponse:
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM clients WHERE enrollment_code = ? AND enrolled = 0",
            (req.enrollment_code,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid enrollment code")
        token = secrets.token_urlsafe(24)
        conn.execute(
            "UPDATE clients SET token = ?, enrolled = 1, hostname = COALESCE(?, hostname), last_seen = ? WHERE id = ?",
            (token, req.hostname, utc_now_iso(), int(row["id"])),
        )
        client_id = int(row["id"])
    await ws_manager.broadcast_admin({"type": "client_enrolled", "client_id": client_id})
    audit("client", client_id, req.hostname or "client", "client_enrolled", {"client_id": client_id})
    return ClientEnrollResponse(token=token, client_id=client_id)


@app.post("/api/client/register", response_model=ClientEnrollResponse)
async def client_register(
    req: ClientRegisterRequest, x_enrollment_key: Optional[str] = Header(default=None)
) -> ClientEnrollResponse:
    require_enrollment_key(x_enrollment_key)
    now = utc_now_iso()
    token = secrets.token_urlsafe(24)
    with db_connect() as conn:
        existing = None
        if req.hostname:
            existing = conn.execute(
                "SELECT * FROM clients WHERE hostname = ? ORDER BY id DESC LIMIT 1",
                (req.hostname,),
            ).fetchone()

        if existing:
            client_id = int(existing["id"])
            conn.execute(
                "UPDATE clients SET name = ?, token = ?, enrolled = 1, last_seen = ? WHERE id = ?",
                (req.name, token, now, client_id),
            )
        else:
            cur = conn.execute(
                "INSERT INTO clients (name, hostname, token, enrolled, created_at, last_seen) VALUES (?, ?, ?, 1, ?, ?)",
                (req.name, req.hostname, token, now, now),
            )
            client_id = int(cur.lastrowid)

    await ws_manager.broadcast_admin({"type": "client_enrolled", "client_id": client_id})
    return ClientEnrollResponse(token=token, client_id=client_id)


@app.post("/api/client/heartbeat")
async def client_heartbeat(
    req: ClientHeartbeatRequest, x_client_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    client = require_client_token(x_client_token)
    client_id = int(client["id"])
    now = utc_now_iso()

    with db_connect() as conn:
        conn.execute(
            "UPDATE clients SET last_seen = ?, hostname = COALESCE(?, hostname) WHERE id = ?",
            (now, req.hostname, client_id),
        )

        for alert in req.alerts:
            conn.execute(
                "INSERT INTO logs (client_id, ts, level, event_type, data_json) VALUES (?, ?, ?, ?, ?)",
                (client_id, now, "alert", alert.get("event_type", "alert"), json.dumps(alert)),
            )

        if req.processes:
            conn.execute(
                "INSERT INTO logs (client_id, ts, level, event_type, data_json) VALUES (?, ?, 'info', 'process_snapshot', ?)",
                (client_id, now, json.dumps({"processes": req.processes[:200]})),
            )
        
        # Log system resources if provided
        if req.cpu_percent is not None or req.ram_percent is not None or req.disk_percent is not None:
            conn.execute(
                "INSERT INTO logs (client_id, ts, level, event_type, data_json) VALUES (?, ?, 'info', 'system_resources', ?)",
                (client_id, now, json.dumps({
                    "cpu_percent": req.cpu_percent,
                    "ram_percent": req.ram_percent,
                    "disk_percent": req.disk_percent
                })),
            )
        
        # Log URL violations
        for url in req.url_violations:
            conn.execute(
                "INSERT INTO logs (client_id, ts, level, event_type, data_json) VALUES (?, ?, ?, ?, ?)",
                (client_id, now, "alert", "url_violation", json.dumps({"url": url})),
            )
        
        # Fetch latest blocked URLs to return to client
        blocked_rows = conn.execute("SELECT pattern FROM blocked_urls WHERE enabled = 1").fetchall()
        blocked_patterns = [r["pattern"] for r in blocked_rows]

    # Broadcast with resource data
    broadcast_data = {
        "type": "heartbeat",
        "client_id": client_id,
        "ts": now,
        "alerts": req.alerts,
        "resources": {
            "cpu": req.cpu_percent,
            "ram": req.ram_percent,
            "disk": req.disk_percent
        }
    }
    
    if req.url_violations:
        broadcast_data["url_violations"] = req.url_violations
    
    await ws_manager.broadcast_admin(broadcast_data)
    return {"ok": True, "blocked_patterns": blocked_patterns}



@app.post("/api/client/logs")
async def client_logs(req: ClientLogsRequest, x_client_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    client = require_client_token(x_client_token)
    client_id = int(client["id"])
    now = utc_now_iso()
    with db_connect() as conn:
        conn.execute(
            "UPDATE clients SET last_seen = ? WHERE id = ?",
            (now, client_id),
        )
        for e in req.events:
            conn.execute(
                "INSERT INTO logs (client_id, ts, level, event_type, data_json) VALUES (?, ?, ?, ?, ?)",
                (client_id, now, e.level, e.event_type, json.dumps(e.data)),
            )
    await ws_manager.broadcast_admin({"type": "logs", "client_id": client_id, "count": len(req.events), "ts": now})
    return {"ok": True}


@app.get("/api/client/commands/poll")
async def client_poll_commands(x_client_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    client = require_client_token(x_client_token)
    client_id = int(client["id"])
    now = utc_now_iso()
    with db_connect() as conn:
        conn.execute("UPDATE clients SET last_seen = ? WHERE id = ?", (now, client_id))
        cmds = conn.execute(
            "SELECT id, ts, command_type, payload_json FROM commands WHERE client_id = ? AND status = 'queued' ORDER BY id ASC LIMIT 20",
            (client_id,),
        ).fetchall()
        cmd_ids = [int(c["id"]) for c in cmds]
        if cmd_ids:
            conn.executemany(
                "UPDATE commands SET status = 'delivered', delivered_at = ? WHERE id = ?",
                [(now, cid) for cid in cmd_ids],
            )

    out = []
    for c in cmds:
        out.append(
            {
                "id": int(c["id"]),
                "ts": c["ts"],
                "command_type": c["command_type"],
                "payload": json.loads(c["payload_json"] or "{}"),
            }
        )
    return {"commands": out}


@app.post("/api/client/commands/{command_id}/executed")
async def client_mark_executed(
    command_id: int,
    x_client_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    client = require_client_token(x_client_token)
    client_id = int(client["id"])
    now = utc_now_iso()
    with db_connect() as conn:
        row = conn.execute(
            "SELECT id FROM commands WHERE id = ? AND client_id = ?",
            (command_id, client_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Command not found")
        conn.execute(
            "UPDATE commands SET status = 'executed', executed_at = ? WHERE id = ?",
            (now, command_id),
        )
    await ws_manager.broadcast_admin({"type": "command_executed", "client_id": client_id, "command_id": command_id, "ts": now})
    return {"ok": True}


@app.get("/api/admin/logs")
async def admin_recent_logs(
    limit: int = 200, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    admin = require_admin(authorization)
    limit = max(1, min(1000, limit))
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT l.id, l.ts, l.level, l.event_type, l.data_json, c.id as client_id, c.name as client_name
            FROM logs l
            JOIN clients c ON c.id = l.client_id
            ORDER BY l.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    out = []
    for r in rows:
        out.append(
            {
                "id": int(r["id"]),
                "ts": r["ts"],
                "level": r["level"],
                "event_type": r["event_type"],
                "data": json.loads(r["data_json"] or "{}"),
                "client": {"id": int(r["client_id"]), "name": r["client_name"]},
            }
        )
    audit("admin", int(admin["admin_id"]), str(admin["username"]), "logs_list", {"limit": limit})
    return {"logs": out}


@app.get("/api/admin/blocked-urls")
async def admin_list_blocked_urls(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    admin = require_admin(authorization)
    with db_connect() as conn:
        rows = conn.execute("SELECT id, pattern, enabled, created_at FROM blocked_urls ORDER BY id ASC").fetchall()
    audit("admin", int(admin["admin_id"]), str(admin["username"]), "blocked_urls_list", {})
    return {"blocked_urls": [dict(r) for r in rows]}


@app.post("/api/admin/blocked-urls")
async def admin_add_blocked_url(
    req: Dict[str, Any], authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    admin = require_admin(authorization)
    pattern = (req.get("pattern") or "").strip()
    if not pattern:
        raise HTTPException(status_code=400, detail="Pattern required")
    
    now = utc_now_iso()
    with db_connect() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO blocked_urls (pattern, enabled, created_at) VALUES (?, 1, ?)",
                (pattern, now)
            )
            url_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Pattern already exists")
    
    await ws_manager.broadcast_admin({"type": "blocked_url_added", "pattern": pattern, "id": url_id})
    audit("admin", int(admin["admin_id"]), str(admin["username"]), "blocked_url_added", {"pattern": pattern})
    
    # Send update command to all clients
    with db_connect() as conn:
        clients = conn.execute("SELECT id FROM clients WHERE enrolled = 1").fetchall()
        blocked_patterns = conn.execute("SELECT pattern FROM blocked_urls WHERE enabled = 1").fetchall()
        patterns_list = [r["pattern"] for r in blocked_patterns]
        
        for client in clients:
            client_id = int(client["id"])
            conn.execute(
                "INSERT INTO commands (client_id, ts, command_type, payload_json, status) VALUES (?, ?, 'update_blocked_urls', ?, 'queued')",
                (client_id, now, json.dumps({"patterns": patterns_list}))
            )
    
    return {"id": url_id, "pattern": pattern}


@app.delete("/api/admin/blocked-urls/{url_id}")
async def admin_delete_blocked_url(
    url_id: int, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    admin = require_admin(authorization)
    with db_connect() as conn:
        row = conn.execute("SELECT pattern FROM blocked_urls WHERE id = ?", (url_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="URL not found")
        pattern = str(row["pattern"])
        conn.execute("DELETE FROM blocked_urls WHERE id = ?", (url_id,))
    
    await ws_manager.broadcast_admin({"type": "blocked_url_removed", "id": url_id})
    audit("admin", int(admin["admin_id"]), str(admin["username"]), "blocked_url_removed", {"pattern": pattern})
    
    # Send update command to all clients
    now = utc_now_iso()
    with db_connect() as conn:
        clients = conn.execute("SELECT id FROM clients WHERE enrolled = 1").fetchall()
        blocked_patterns = conn.execute("SELECT pattern FROM blocked_urls WHERE enabled = 1").fetchall()
        patterns_list = [r["pattern"] for r in blocked_patterns]
        
        for client in clients:
            client_id = int(client["id"])
            conn.execute(
                "INSERT INTO commands (client_id, ts, command_type, payload_json, status) VALUES (?, ?, 'update_blocked_urls', ?, 'queued')",
                (client_id, now, json.dumps({"patterns": patterns_list}))
            )
    
    return {"ok": True}


@app.post("/api/admin/commands/broadcast")
async def admin_broadcast_command(
    req: AdminCommandRequest, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    admin = require_admin(authorization)
    ts = utc_now_iso()
    
    # Get all online clients (last_seen within 15 seconds)
    with db_connect() as conn:
        threshold = datetime.now(timezone.utc).replace(microsecond=0)
        threshold = datetime.fromtimestamp(threshold.timestamp() - 15, tz=timezone.utc).isoformat()
        
        clients = conn.execute(
            "SELECT id, name FROM clients WHERE enrolled = 1 AND last_seen > ?",
            (threshold,)
        ).fetchall()
        
        if not clients:
            raise HTTPException(status_code=400, detail="No online clients")
        
        command_ids = []
        for client in clients:
            client_id = int(client["id"])
            cur = conn.execute(
                "INSERT INTO commands (client_id, ts, command_type, payload_json, status) VALUES (?, ?, ?, ?, 'queued')",
                (client_id, ts, req.command_type, json.dumps(req.payload))
            )
            command_ids.append(int(cur.lastrowid))
    
    await ws_manager.broadcast_admin({
        "type": "commands_broadcast",
        "command_type": req.command_type,
        "client_count": len(clients),
        "ts": ts
    })
    
    audit(
        "admin",
        int(admin["admin_id"]),
        str(admin["username"]),
        "commands_broadcast",
        {"command_type": req.command_type, "client_count": len(clients), "payload": req.payload}
    )
    
    return {"command_ids": command_ids, "client_count": len(clients)}


@app.post("/api/client/screenshot")
async def client_upload_screenshot(
    req: Dict[str, Any], x_client_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    client = require_client_token(x_client_token)
    client_id = int(client["id"])
    
    # Expecting base64 encoded image data
    image_data = req.get("image_data")
    if not image_data:
        raise HTTPException(status_code=400, detail="Missing image_data")
    
    import base64
    import os
    
    # Create screenshots directory if it doesn't exist
    screenshots_dir = os.path.join(os.path.dirname(__file__), "static", "screenshots")
    os.makedirs(screenshots_dir, exist_ok=True)
    
    # Generate filename
    ts = utc_now_iso()
    ext = req.get("format", "png")
    filename = f"client_{client_id}_{ts.replace(':', '-').replace('.', '-')}.{ext}"
    filepath = os.path.join(screenshots_dir, filename)
    
    # Decode and save
    try:
        img_bytes = base64.b64decode(image_data)
        with open(filepath, "wb") as f:
            f.write(img_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid image data: {e}")
    
    # Store in database
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO screenshots (client_id, filename, ts) VALUES (?, ?, ?)",
            (client_id, filename, ts)
        )
    
    await ws_manager.broadcast_admin({
        "type": "screenshot_captured",
        "client_id": client_id,
        "filename": filename,
        "ts": ts
    })
    
    return {"ok": True, "filename": filename}


@app.get("/api/admin/screenshots/{client_id}")
async def admin_list_screenshots(
    client_id: int, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    admin = require_admin(authorization)
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, filename, ts FROM screenshots WHERE client_id = ? ORDER BY id DESC LIMIT 50",
            (client_id,)
        ).fetchall()
    return {"screenshots": [dict(r) for r in rows]}
