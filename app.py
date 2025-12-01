from flask import Flask, render_template
import os
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool as pg_pool
from contextlib import contextmanager
from datetime import datetime

load_dotenv()

DATABASE_URL = os.getenv("NEON_DATABASE_URL") or os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("NEON_DATABASE_URL not set. Create a .env file or set the environment variable.")

# Connection pool (fallback to direct connect if pool creation fails)
_pool = None
try:
    _pool = pg_pool.SimpleConnectionPool(1, int(os.getenv("DB_MAX_CONN", "10")), DATABASE_URL, cursor_factory=RealDictCursor)
except Exception:
    _pool = None


@contextmanager
def get_conn():
    """Yield a DB connection; return to pool when used."""
    if _pool:
        conn = _pool.getconn()
        try:
            yield conn
        finally:
            try:
                _pool.putconn(conn)
            except Exception:
                conn.close()
    else:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        try:
            yield conn
        finally:
            conn.close()


app = Flask(__name__)


@app.route("/")
def index():
    quiz_questions = []
    users = []
    error = None

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, category_id, question_text, audio_path, difficulty, created_at FROM quiz_questions"
                )
                quiz_questions = cur.fetchall()
                cur.execute(
                    "SELECT id, username, email, created_at FROM users"
                )
                users = cur.fetchall()
    except Exception as e:
        error = str(e)

    def normalize(rows_list):
        for r in rows_list:
            ca = r.get("created_at")
            if ca and not isinstance(ca, str):
                try:
                    r["created_at"] = ca.isoformat()
                except Exception:
                    r["created_at"] = str(ca)

    normalize(quiz_questions)
    normalize(users)

    return render_template("index.html", problems=quiz_questions, users=users, error=error)


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
