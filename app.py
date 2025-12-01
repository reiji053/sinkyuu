from flask import Flask, render_template, request, redirect, url_for, flash
import os
from pathlib import Path
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool as pg_pool
from contextlib import contextmanager
from datetime import datetime

# Load .env from the directory where app.py sits (more reliable than implicit lookup)
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / '.env')

DATABASE_URL = os.getenv("NEON_DATABASE_URL") or os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("NEON_DATABASE_URL not set. Create a .env file or set the environment variable.")
else:
    # Print a masked version when in debug for easier troubleshooting
    if os.getenv("FLASK_DEBUG", "0") == "1":
        masked = (DATABASE_URL[:60] + '...') if len(DATABASE_URL) > 60 else DATABASE_URL
        print("Using NEON_DATABASE_URL:", masked)

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
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret")


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

    # Pass quiz_questions as the template expects that variable name
    return render_template("index.html", quiz_questions=quiz_questions, users=users, error=error)


# --- CRUD routes for quiz_questions -------------------------------------------------
@app.route("/quiz/new", methods=("GET", "POST"))
def quiz_new():
    if request.method == "POST":
        category_id = request.form.get("category_id") or None
        question_text = request.form.get("question_text") or ""
        audio_path = request.form.get("audio_path") or None
        difficulty = request.form.get("difficulty") or None
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO quiz_questions (category_id, question_text, audio_path, difficulty, created_at) VALUES (%s, %s, %s, %s, now())",
                        (category_id, question_text, audio_path, difficulty),
                    )
                    conn.commit()
            flash("問題を作成しました。", "success")
        except Exception as ex:
            flash(f"作成に失敗しました: {ex}", "danger")
        return redirect(url_for("index"))
    # GET
    return render_template("quiz_form.html", quiz=None)


@app.route("/quiz/<int:quiz_id>/edit", methods=("GET", "POST"))
def quiz_edit(quiz_id):
    if request.method == "POST":
        category_id = request.form.get("category_id") or None
        question_text = request.form.get("question_text") or ""
        audio_path = request.form.get("audio_path") or None
        difficulty = request.form.get("difficulty") or None
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE quiz_questions SET category_id=%s, question_text=%s, audio_path=%s, difficulty=%s WHERE id=%s",
                        (category_id, question_text, audio_path, difficulty, quiz_id),
                    )
                    conn.commit()
            flash("問題を更新しました。", "success")
        except Exception as ex:
            flash(f"更新に失敗しました: {ex}", "danger")
        return redirect(url_for("index"))

    # GET: load existing
    quiz = None
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, category_id, question_text, audio_path, difficulty FROM quiz_questions WHERE id=%s", (quiz_id,))
                quiz = cur.fetchone()
    except Exception as ex:
        flash(f"読み込みに失敗しました: {ex}", "danger")
        return redirect(url_for("index"))
    return render_template("quiz_form.html", quiz=quiz)


@app.route("/quiz/<int:quiz_id>/delete", methods=("POST",))
def quiz_delete(quiz_id):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM quiz_questions WHERE id=%s", (quiz_id,))
                conn.commit()
        flash("問題を削除しました。", "success")
    except Exception as ex:
        flash(f"削除に失敗しました: {ex}", "danger")
    return redirect(url_for("index"))


# --- CRUD routes for users ---------------------------------------------------------
@app.route("/user/new", methods=("GET", "POST"))
def user_new():
    if request.method == "POST":
        username = request.form.get("username") or ""
        email = request.form.get("email") or ""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO users (username, email, created_at) VALUES (%s, %s, now())",
                        (username, email),
                    )
                    conn.commit()
            flash("ユーザーを作成しました。", "success")
        except Exception as ex:
            flash(f"作成に失敗しました: {ex}", "danger")
        return redirect(url_for("index"))
    return render_template("user_form.html", user=None)


@app.route("/user/<int:user_id>/edit", methods=("GET", "POST"))
def user_edit(user_id):
    if request.method == "POST":
        username = request.form.get("username") or ""
        email = request.form.get("email") or ""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET username=%s, email=%s WHERE id=%s",
                        (username, email, user_id),
                    )
                    conn.commit()
            flash("ユーザーを更新しました。", "success")
        except Exception as ex:
            flash(f"更新に失敗しました: {ex}", "danger")
        return redirect(url_for("index"))

    user = None
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, email FROM users WHERE id=%s", (user_id,))
                user = cur.fetchone()
    except Exception as ex:
        flash(f"読み込みに失敗しました: {ex}", "danger")
        return redirect(url_for("index"))
    return render_template("user_form.html", user=user)


@app.route("/user/<int:user_id>/delete", methods=("POST",))
def user_delete(user_id):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
                conn.commit()
        flash("ユーザーを削除しました。", "success")
    except Exception as ex:
        flash(f"削除に失敗しました: {ex}", "danger")
    return redirect(url_for("index"))


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
