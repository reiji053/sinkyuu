
from flask import Flask, redirect, request, session, render_template
from google_auth_oauthlib.flow import Flow
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from flask import request, redirect, url_for, flash

# =============================
# 初期設定
# =============================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_SECRETS_FILE = "client_secret.json"
DATABASE_URL = os.environ["DATABASE_URL"]

# =============================
# DB 接続関数
# =============================
def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.DictCursor
    )

# =============================
# DB 初期化
# =============================
def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            name TEXT,
            google_login BOOLEAN DEFAULT FALSE
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

# =============================
# ページ
# =============================
@app.route("/")
def title_page():
    return render_template("title.html")

# =============================
# サインアップ
# =============================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        hashed_pw = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_pw)
            )
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return "そのメールアドレスはすでに登録されています"
        finally:
            cur.close()
            conn.close()

        return redirect("/signin")

    return render_template("signup.html")

# =============================
# サインイン
# =============================
@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password FROM users WHERE email = %s",
            (email,)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and user["password"] and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            return redirect("/select")
        else:
            return "メールアドレスまたはパスワードが違います"

    return render_template("signin.html")

# =============================
# Email サインイン（signup_email.html 用）
# =============================
def get_db_connection():
    return psycopg2.connect(
        os.environ["DATABASE_URL"],
        sslmode="require"
    )

@app.route("/signup-email", methods=["GET", "POST"])
def signup_email():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO users (email, password_hash)
                VALUES (%s, %s)
                """,
                (email, password_hash),
            )

            conn.commit()
            cur.close()
            conn.close()

            return redirect(url_for("difficulty"))  # 次の画面へ

        except psycopg2.errors.UniqueViolation:
            flash("This email is already registered.")
            return redirect(url_for("signup_email"))

        except Exception as e:
            print(e)
            flash("Something went wrong.")
            return redirect(url_for("signup_email"))

    return render_template("signup_email.html")


# =============================
# パスワード忘れ
# =============================
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]
        return f"パスワードリセット（未実装）: {email}"

    return render_template("forgot.html")

# =============================
# Google ログイン
# =============================
@app.route("/auth/google")
def auth_google():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        redirect_uri="http://localhost:8000/auth/google/callback"
    )

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/auth/google/callback")
def google_callback():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        redirect_uri="http://localhost:8000/auth/google/callback"
    )

    flow.fetch_token(authorization_response=request.url)

    from google.oauth2 import id_token
    from google.auth.transport import requests

    id_info = id_token.verify_oauth2_token(
        flow.credentials._id_token,
        requests.Request(),
        audience=flow.client_config["client_id"]
    )

    email = id_info["email"]
    name = id_info.get("name", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user:
        cur.execute(
            "INSERT INTO users (email, name, google_login) VALUES (%s, %s, TRUE) RETURNING id",
            (email, name)
        )
        user_id = cur.fetchone()["id"]
        conn.commit()
    else:
        user_id = user["id"]

    cur.close()
    conn.close()

    session["user_id"] = user_id
    return redirect("/select")

# =============================
# ログアウト
# =============================
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect("/signin")

# =============================
# 選択・問題画面
# =============================
@app.route("/difficulty")
def difficulty():
    return render_template("difficulty.html")

@app.route("/frequency")
def frequency():
    return render_template("frequency.html")

@app.route("/ready")
def ready():
    return render_template("ready.html")

@app.route("/select")
def select():
    return render_template("select.html")

@app.route("/question")
def question():
    genre = request.args.get("genre")
    level = request.args.get("level")

    return render_template(
        "question.html",
        genre=genre,
        level=level
    )

@app.route("/db-test")
def db_test():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return f"DB 接続成功！<br>{result[0]}"
    except Exception as e:
        return f"DB 接続失敗 ❌<br>{e}"


# =============================
# 実行
# =============================
if __name__ == "__main__":
    app.run(debug=True, port=8000)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
from pathlib import Path
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool as pg_pool
from werkzeug.security import generate_password_hash
from contextlib import contextmanager

# Load .env
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / '.env')

DATABASE_URL = os.getenv("NEON_DATABASE_URL") or os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("NEON_DATABASE_URL not set. Create a .env file or set the environment variable.")

# Connection pool (fallback)
_pool = None
try:
    _pool = pg_pool.SimpleConnectionPool(1, int(os.getenv("DB_MAX_CONN", "10")), DATABASE_URL, cursor_factory=RealDictCursor)
except Exception:
    _pool = None


@contextmanager
def get_conn():
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
    return render_template("index.html")


@app.route("/admin")
def admin():
    quiz_questions = users = quiz_choices = []
    error = None
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM quiz_questions")
                quiz_questions = cur.fetchall()
                cur.execute("SELECT id, name, email, password_hash, created_at FROM users")
                users = cur.fetchall()
                cur.execute("SELECT * FROM quiz_choices")
                quiz_choices = cur.fetchall()
    except Exception as e:
        error = str(e)

    def _normalize(rows):
        for r in rows:
            ca = r.get("created_at")
            if ca and not isinstance(ca, str):
                try:
                    r["created_at"] = ca.isoformat()
                except Exception:
                    r["created_at"] = str(ca)

    for lst in (quiz_questions, users, quiz_choices):
        _normalize(lst)

    return render_template("admin.html", quiz_questions=quiz_questions, users=users, quiz_choices=quiz_choices, error=error)


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

    quiz = None
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM quiz_questions WHERE id=%s", (quiz_id,))
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
        name = request.form.get("name") or ""
        email = request.form.get("email") or ""
        password = request.form.get("password") or None
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    pw_hash = None
                    if password:
                        pw_hash = generate_password_hash(password)
                    cur.execute(
                        "INSERT INTO users (name, email, password_hash, created_at) VALUES (%s, %s, %s, now())",
                        (name, email, pw_hash),
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
        name = request.form.get("name") or ""
        email = request.form.get("email") or ""
        password = request.form.get("password") or None
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    if password:
                        pw_hash = generate_password_hash(password)
                        cur.execute(
                            "UPDATE users SET name=%s, email=%s, password_hash=%s WHERE id=%s",
                            (name, email, pw_hash, user_id),
                        )
                    else:
                        cur.execute(
                            "UPDATE users SET name=%s, email=%s WHERE id=%s",
                            (name, email, user_id),
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
                cur.execute("SELECT id, name, email, password_hash, created_at FROM users WHERE id=%s", (user_id,))
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


@app.route("/api/quiz/category/<int:category_id>")
def quizzes_by_category(category_id):
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM quiz_questions WHERE category_id=%s", (category_id,))
                questions = cur.fetchall()
                for q in questions:
                    cur.execute(
                        "SELECT * FROM quiz_choices WHERE question_id=%s ORDER BY display_order",
                        (q.get("id"),),
                    )
                    q["choices"] = cur.fetchall()
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

    def _norm_rows(rows):
        for r in rows:
            for k in ("created_at", "updated_at"):
                v = r.get(k)
                if v and not isinstance(v, str):
                    try:
                        r[k] = v.isoformat()
                    except Exception:
                        r[k] = str(v)

    _norm_rows(questions)
    return jsonify({"category_id": category_id, "questions": questions})


@app.route("/api/quiz/category/<int:category_id>/variants")
def quiz_variants(category_id):
    count = 1
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM quiz_questions WHERE category_id=%s ORDER BY id LIMIT %s", (category_id, count))
                questions = cur.fetchall()
                for q in questions:
                    cur.execute("SELECT * FROM quiz_choices WHERE question_id=%s ORDER BY display_order", (q.get("id"),))
                    q["choices"] = cur.fetchall()
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

    def _norm(rows):
        for r in rows:
            for k in ("created_at", "updated_at"):
                v = r.get(k)
                if v and not isinstance(v, str):
                    try:
                        r[k] = v.isoformat()
                    except Exception:
                        r[k] = str(v)

    _norm(questions)
    return jsonify({"category_id": category_id, "count": len(questions), "questions": questions})


@app.route('/api/quiz/answer', methods=('POST',))
def quiz_answer():
    payload = request.get_json(silent=True) or {}
    choice_id = payload.get('choice_id')
    question_id = payload.get('question_id')

    if not choice_id:
        return jsonify({'error': 'choice_id is required'}), 400

    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, question_id, is_correct, explanation FROM quiz_choices WHERE id=%s", (choice_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({'error': 'choice not found'}), 404

                if question_id is not None and int(row.get('question_id')) != int(question_id):
                    return jsonify({'error': 'choice does not belong to the provided question_id'}), 400

                correct = bool(row.get('is_correct'))
                return jsonify({'choice_id': row.get('id'), 'question_id': row.get('question_id'), 'correct': correct, 'explanation': row.get('explanation')})
    except Exception as ex:
        return jsonify({'error': str(ex)}), 500


@app.route("/quiz/play/<int:category_id>")
def quiz_play(category_id):
    try:
        count = int(request.args.get("count", 1))
    except Exception:
        count = 1

    start_id = request.args.get('start_id')
    try:
        offset = int(request.args.get("offset", 0))
    except Exception:
        offset = 0

    questions = []
    has_next = False
    next_start_id = None
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if start_id is not None:
                    try:
                        sid = int(start_id)
                    except Exception:
                        sid = None
                    if sid is not None:
                        cur.execute("SELECT * FROM quiz_questions WHERE category_id=%s AND id >= %s ORDER BY id LIMIT 1", (category_id, sid))
                        questions = cur.fetchall()
                        for q in questions:
                            cur.execute("SELECT * FROM quiz_choices WHERE question_id=%s ORDER BY display_order", (q.get("id"),))
                            q["choices"] = cur.fetchall()
                        if questions:
                            cur.execute("SELECT id FROM quiz_questions WHERE category_id=%s AND id > %s ORDER BY id LIMIT 1", (category_id, questions[0].get('id')))
                            nx = cur.fetchone()
                            if nx:
                                has_next = True
                                next_start_id = nx.get('id')
                    else:
                        start_id = None
                if start_id is None:
                    cur.execute("SELECT * FROM quiz_questions WHERE category_id=%s ORDER BY id LIMIT %s OFFSET %s", (category_id, count + 1, offset))
                    fetched = cur.fetchall()
                    has_next = len(fetched) > count
                    questions = fetched[:count]
                    for q in questions:
                        cur.execute("SELECT * FROM quiz_choices WHERE question_id=%s ORDER BY display_order", (q.get("id"),))
                        q["choices"] = cur.fetchall()
                    if has_next:
                        next_start_id = fetched[count].get('id')
    except Exception as ex:
        flash(f"読み込みに失敗しました: {ex}", "danger")
        return redirect(url_for("index"))

    for r in questions:
        ca = r.get("created_at")
        ua = r.get("updated_at")
        if ca and not isinstance(ca, str):
            try:
                r["created_at"] = ca.isoformat()
            except Exception:
                r["created_at"] = str(ca)
        if ua and not isinstance(ua, str):
            try:
                r["updated_at"] = ua.isoformat()
            except Exception:
                r["updated_at"] = str(ua)

    safe_questions = []
    for q in questions:
        q_copy = dict(q)
        safe_choices = []
        for c in q.get('choices', []):
            c_copy = dict(c)
            c_copy.pop('is_correct', None)
            safe_choices.append(c_copy)
        q_copy['choices'] = safe_choices
        safe_questions.append(q_copy)

    next_offset = offset + count

    return render_template("quiz_play.html", category_id=category_id, questions=safe_questions, count=count, offset=offset, has_next=has_next, next_offset=next_offset, next_start_id=next_start_id)


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
