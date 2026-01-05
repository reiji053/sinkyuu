from flask import Flask, redirect, request, session, render_template, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
import os
import hashlib
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
import secrets
from datetime import datetime, timedelta
import time
from collections import deque


# =============================
# 初期設定
# =============================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "dev-secret-key"
DATABASE_URL = os.environ.get("DATABASE_URL")


def _is_production() -> bool:
    return (
        (os.environ.get("FLASK_ENV") or "").lower() == "production"
        or (os.environ.get("ENV") or "").lower() == "production"
        or (os.environ.get("VERCEL_ENV") or "").lower() == "production"
    )


IS_PRODUCTION = _is_production()

# セッションCookieの安全設定（本番はHTTPS前提）
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
)

if app.secret_key == "dev-secret-key" and IS_PRODUCTION:
    raise RuntimeError(
        "本番環境では FLASK_SECRET_KEY を必ず設定してください（dev-secret-key は危険です）。"
    )


def csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def _validate_csrf() -> None:
    session_token = session.get("_csrf_token")
    form_token = request.form.get("_csrf_token")
    if not session_token or not form_token:
        abort(400)
    if not secrets.compare_digest(str(session_token), str(form_token)):
        abort(400)


@app.before_request
def _csrf_protect():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        # static などは対象外
        if request.endpoint == "static":
            return
        _validate_csrf()


_LOGIN_ATTEMPTS: dict[str, deque[float]] = {}


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_rate_limited(key: str, *, limit: int = 10, window_seconds: int = 15 * 60) -> bool:
    now = time.time()
    q = _LOGIN_ATTEMPTS.get(key)
    if q is None:
        q = deque()
        _LOGIN_ATTEMPTS[key] = q

    cutoff = now - window_seconds
    while q and q[0] < cutoff:
        q.popleft()

    return len(q) >= limit


def _record_attempt(key: str, *, window_seconds: int = 15 * 60) -> None:
    now = time.time()
    q = _LOGIN_ATTEMPTS.get(key)
    if q is None:
        q = deque()
        _LOGIN_ATTEMPTS[key] = q

    cutoff = now - window_seconds
    while q and q[0] < cutoff:
        q.popleft()
    q.append(now)


def _clear_attempts(key: str) -> None:
    _LOGIN_ATTEMPTS.pop(key, None)


def require_database_url():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL が未設定です。.env に DATABASE_URL=... を設定するか、環境変数で指定してください。"
        )

# =============================
# DB 接続関数
# =============================
def get_db():
    require_database_url()
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
            name TEXT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            native_language TEXT,
            current_level INTEGER,
            google_id TEXT,
            google_login BOOLEAN DEFAULT FALSE,
            profile_picture_url TEXT,
            last_login_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # 既存DBが古い定義でも動くように不足カラムを補完
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS native_language TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS current_level INTEGER")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_login BOOLEAN DEFAULT FALSE")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture_url TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()")

    # 旧カラム password が残っている場合は移行（あればでOK）
    cur.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name='users' AND column_name='password'
            ) THEN
                UPDATE users
                SET password_hash = COALESCE(password_hash, password)
                WHERE password_hash IS NULL;
            END IF;
        END
        $$;
        """
    )

    cur.execute("""
        CREATE TABLE IF NOT EXISTS badges (
            id SERIAL PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_badges (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            badge_id INTEGER NOT NULL REFERENCES badges(id) ON DELETE CASCADE,
            acquired_at TIMESTAMP DEFAULT NOW(),
            PRIMARY KEY (user_id, badge_id)
        )
    """)

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        )
        """
    )

    conn.commit()
    cur.close()
    conn.close()

if DATABASE_URL:
    init_db()
else:
    print("[WARN] DATABASE_URL が未設定のため DB 初期化をスキップします")


def verify_password(stored_hash: str | None, password: str) -> bool:
    if not stored_hash:
        return False

    # werkzeug形式（pbkdf2:sha256:... など）
    if ":" in stored_hash:
        try:
            return check_password_hash(stored_hash, password)
        except Exception:
            return False

    # 旧データ対策: 32桁hex（例: MD5）
    if len(stored_hash) == 32 and all(c in "0123456789abcdef" for c in stored_hash.lower()):
        return hashlib.md5(password.encode("utf-8")).hexdigest() == stored_hash.lower()

    return False


def fetch_user_for_login(cur, identifier: str):
    identifier = (identifier or "").strip()
    if not identifier:
        return None

    # 数字だけなら user_id 扱い（既存UIがUser IDだったため）
    if identifier.isdigit():
        cur.execute(
            "SELECT id, password_hash FROM users WHERE id = %s",
            (int(identifier),),
        )
        return cur.fetchone()

    # それ以外は email 扱い
    cur.execute(
        "SELECT id, password_hash FROM users WHERE email = %s",
        (identifier,),
    )
    return cur.fetchone()

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
        # 既存テンプレでは /signup にPOSTしない想定だが、保険として残す
        email = request.form.get("email")
        password = request.form.get("password")
        name = (request.form.get("name") or "").strip() or None
        if not email or not password:
            return "パラメータが不足しています", 400

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO users (email, name, password_hash, google_login, created_at, updated_at)
                VALUES (%s, %s, %s, FALSE, NOW(), NOW())
                """,
                (email, name, password_hash),
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
        # templates/signin.html は userid という名前なので両対応
        identifier = (request.form.get("email") or request.form.get("userid") or "").strip()
        password = request.form.get("password") or ""

        rl_key = f"signin:{_client_ip()}"
        if _is_rate_limited(rl_key):
            return "試行回数が多すぎます。しばらく待ってから再試行してください", 429

        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            user = fetch_user_for_login(cur, identifier)

            if user and verify_password(user.get("password_hash"), password):
                session["user_id"] = user["id"]
                _clear_attempts(rl_key)
                cur.execute(
                    "UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = %s",
                    (user["id"],),
                )
                conn.commit()
                return redirect("/select")

        conn.close()
        _record_attempt(rl_key)
        return "メールアドレスまたはパスワードが違います"

    return render_template("signin.html")

# =============================
# Email サインイン（signup_email.html 用）
# =============================
def get_db_connection():
    require_database_url()
    database_url = DATABASE_URL or ""
    sslmode = os.environ.get("PGSSLMODE")
    if not sslmode:
        # ローカルの Postgres は SSL 無効なことが多いので推測する（本番は require を既定）
        if "localhost" in database_url or "127.0.0.1" in database_url:
            sslmode = "disable"
        else:
            sslmode = "require"

    return psycopg2.connect(database_url, sslmode=sslmode)

@app.route("/signup-email", methods=["GET", "POST"])
def signup_email():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip() or None
        email = request.form["email"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO users (email, name, password_hash, google_login, created_at, updated_at)
                VALUES (%s, %s, %s, FALSE, NOW(), NOW())
                RETURNING id
                """,
                (email, name, password_hash),
            )

            new_user = cur.fetchone()
            if new_user:
                session["user_id"] = new_user[0]

            conn.commit()
            return redirect("/select")

        except RuntimeError as e:
            # DATABASE_URL 未設定など
            flash(str(e))
            return redirect(url_for("signup_email"))

        except psycopg2.errors.UniqueViolation:
            if conn:
                conn.rollback()
            flash("This email is already registered.")
            return redirect(url_for("signup_email"))

        except Exception as e:
            if conn:
                conn.rollback()
            print(e)
            flash("Something went wrong. (DB connection / config may be missing)")
            return redirect(url_for("signup_email"))

        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    conn.close()

    return render_template("signup_email.html")


@app.route("/signin-email", methods=["POST"])
def signin_email():
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""

    rl_key = f"signin-email:{_client_ip()}"
    if _is_rate_limited(rl_key):
        return "試行回数が多すぎます。しばらく待ってから再試行してください", 429

    conn = get_db_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        user = fetch_user_for_login(cur, email)

        if user and verify_password(user.get("password_hash"), password):
            session["user_id"] = user["id"]
            _clear_attempts(rl_key)
            cur.execute(
                "UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = %s",
                (user["id"],),
            )
            conn.commit()
            return redirect("/select")

    conn.close()
    _record_attempt(rl_key)
    return "メールアドレスまたはパスワードが違います"


# =============================
# パスワード忘れ
# =============================
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        if not email:
            flash("Email is required.")
            return redirect(url_for("forgot"))

        # メール送信は未実装のため、開発用にリセットURLを画面に表示する。
        # （存在しないメールでも同じメッセージにして、ユーザー有無を漏らさない）
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            if user:
                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                # DB側は TIMESTAMP (tzなし) なので、UTCのnaive datetimeで統一
                expires_at = datetime.utcnow() + timedelta(hours=1)
                cur.execute(
                    """
                    INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                    VALUES (%s, %s, %s)
                    """,
                    (user["id"], token_hash, expires_at),
                )
                conn.commit()

                reset_url = url_for("reset_password", token=raw_token, _external=True)
                flash(f"Reset link (valid 1 hour): {reset_url}")
            else:
                flash("If the email is registered, a reset link will be shown here.")

        except RuntimeError as e:
            flash(str(e))
        except Exception as e:
            if conn:
                conn.rollback()
            print(e)
            flash("Something went wrong.")
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    conn.close()

        return redirect(url_for("forgot"))

    return render_template("forgot.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = (request.args.get("token") or "").strip()
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        new_password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not token:
            flash("Invalid or missing token.")
            return redirect(url_for("forgot"))
        if not new_password:
            flash("Password is required.")
            return redirect(url_for("reset_password", token=token))
        if new_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("reset_password", token=token))

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.utcnow()

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                """
                SELECT id, user_id, expires_at, used_at
                FROM password_reset_tokens
                WHERE token_hash = %s
                """,
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                flash("This reset link is invalid.")
                return redirect(url_for("forgot"))

            if row.get("used_at") is not None:
                flash("This reset link has already been used.")
                return redirect(url_for("forgot"))

            expires_at = row.get("expires_at")
            if expires_at is None or expires_at < now:
                flash("This reset link has expired.")
                return redirect(url_for("forgot"))

            new_hash = generate_password_hash(new_password)
            cur.execute(
                "UPDATE users SET password_hash = %s, updated_at = NOW() WHERE id = %s",
                (new_hash, row["user_id"]),
            )
            cur.execute(
                "UPDATE password_reset_tokens SET used_at = NOW() WHERE id = %s",
                (row["id"],),
            )
            conn.commit()
            flash("Password updated. Please sign in.")
            return redirect(url_for("signin"))

        except RuntimeError as e:
            flash(str(e))
            return redirect(url_for("forgot"))
        except Exception as e:
            if conn:
                conn.rollback()
            print(e)
            flash("Something went wrong.")
            return redirect(url_for("reset_password", token=token))
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    conn.close()

    # GET
    if not token:
        flash("Invalid or missing token.")
        return redirect(url_for("forgot"))
    return render_template("reset_password.html", token=token)



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

def level_to_int(level):
    return {
        "Easy": 1,
        "Normal": 2,
        "Difficult": 3
    }.get(level)


def _ensure_default_badges(cur):
    defaults = [
        ("profile_opened", "プロフィール開設", "プロフィールページを開いた"),
        ("first_5_questions", "5問チャレンジャー", "合計5問プレイ（暫定）"),
    ]

    for code, name, description in defaults:
        cur.execute(
            """
            INSERT INTO badges (code, name, description)
            VALUES (%s, %s, %s)
            ON CONFLICT (code) DO NOTHING
            """,
            (code, name, description),
        )


def _grant_badge(cur, user_id: int, badge_code: str):
    cur.execute(
        """
        INSERT INTO user_badges (user_id, badge_id)
        SELECT %s, id FROM badges WHERE code = %s
        ON CONFLICT DO NOTHING
        """,
        (user_id, badge_code),
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # テーブルが未作成でも落ちないよう保険
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS badges (
                    id SERIAL PRIMARY KEY,
                    code TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_badges (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    badge_id INTEGER NOT NULL REFERENCES badges(id) ON DELETE CASCADE,
                    acquired_at TIMESTAMP DEFAULT NOW(),
                    PRIMARY KEY (user_id, badge_id)
                )
                """
            )

            _ensure_default_badges(cur)

            cur.execute("SELECT id, email, name FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                session.pop("user_id", None)
                conn.commit()
                return redirect("/signin")

            if request.method == "POST":
                new_name = (request.form.get("name") or "").strip()
                cur.execute(
                    "UPDATE users SET name = %s WHERE id = %s",
                    (new_name if new_name else None, user_id),
                )
                user["name"] = new_name if new_name else None

            # 暫定：プロフィールを開いたらバッジ付与
            _grant_badge(cur, int(user_id), "profile_opened")

            # 暫定：5問以上プレイしていたらバッジ付与
            played = int(session.get("question_count") or 0)
            if played >= 5:
                _grant_badge(cur, int(user_id), "first_5_questions")

            cur.execute(
                """
                SELECT
                    b.code,
                    b.name,
                    b.description,
                    (ub.user_id IS NOT NULL) AS earned
                FROM badges b
                LEFT JOIN user_badges ub
                    ON ub.badge_id = b.id AND ub.user_id = %s
                ORDER BY b.id
                """,
                (user_id,),
            )
            badges = cur.fetchall()

        conn.commit()
    finally:
        conn.close()

    return render_template("profile.html", user=user, badges=badges)


@app.route("/settings")
def settings():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")
    app_language = session.get("app_language") or "English"
    return render_template("settings.html", app_language=app_language)


@app.route("/settings/language", methods=["GET", "POST"])
def settings_language():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")

    languages = ["English", "Hindi", "Japanese"]
    current = session.get("app_language") or "English"

    if request.method == "POST":
        selected = (request.form.get("language") or "").strip()
        if selected in languages:
            session["app_language"] = selected
        return redirect("/settings")

    return render_template("settings_language.html", languages=languages, current=current)


@app.route("/settings/help")
def settings_help():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")
    return render_template("settings_stub.html", title="Help / FAQ")


@app.route("/settings/feedback")
def settings_feedback():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")
    return render_template("settings_stub.html", title="Feedback")


@app.route("/settings/terms")
def settings_terms():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")
    return render_template("settings_stub.html", title="Terms of Service")


@app.route("/settings/privacy")
def settings_privacy():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")
    return render_template("settings_stub.html", title="Privacy Policy")

@app.route("/question", methods=["GET", "POST"])
def question():
    genre_en = (request.args.get("genre") or "").strip()
    level = request.args.get("level")
    reset = request.args.get("reset")

    if not genre_en or not level:
        return "パラメータが不足しています"

    # Shuffle はカテゴリ指定なしで出題
    genre_filter = None if genre_en.lower() == "shuffle" else genre_en

    if reset == "1":
        # クイズの状態だけリセットしたいが、ログイン状態まで消すと
        # /profile などで再ログインが必要になってしまうため保持する。
        preserved_user_id = session.get("user_id")
        preserved_csrf = session.get("_csrf_token")
        session.clear()
        if preserved_user_id:
            session["user_id"] = preserved_user_id
        if preserved_csrf:
            session["_csrf_token"] = preserved_csrf

    level_map = {
        "Easy": 1,
        "Normal": 2,
        "Difficult": 3
    }
    difficulty = level_map.get(level)
    if difficulty is None:
        return "不正なレベルです"

    # =========================
    # 初期化
    # =========================
    if "used_question_ids" not in session:
        session["used_question_ids"] = []
        session["question_count"] = 0
        session["correct_count"] = 0

    # =========================
    # POST（Next）
    # =========================
    if request.method == "POST":
        question_id_raw = request.form.get("question_id")
        if not question_id_raw:
            return "question_id が不足しています"
        question_id = int(question_id_raw)
        is_correct = request.form.get("is_correct")

        session["used_question_ids"].append(question_id)
        session["question_count"] += 1
        
        if is_correct == "1":
            session["correct_count"] += 1

        return redirect(url_for("question", genre=genre_en, level=level))

    def _fetch_next_question(cur, *, strict_difficulty: bool):
        where_parts = ["q.id NOT IN %s"]
        params: list[object] = [tuple(session["used_question_ids"]) or (0,)]

        if genre_filter is not None:
            # 既存DBによっては name_en が無い/値が違う可能性があるため name も許容
            where_parts.append("(c.name_en = %s OR c.name = %s)")
            params.extend([genre_filter, genre_filter])

        if strict_difficulty:
            where_parts.append("q.difficulty = %s")
            params.append(difficulty)

        sql = f"""
            SELECT
                q.id,
                q.question_text,
                q.explanation,
                c.name AS category_name,
                ci.image_data
            FROM quiz_questions q
            JOIN quiz_categories c
                ON q.category_id = c.id
            LEFT JOIN category_images ci
                ON ci.category_id = c.id
            WHERE {' AND '.join(where_parts)}
            ORDER BY q.id
            LIMIT 1
        """
        cur.execute(sql, tuple(params))
        return cur.fetchone()

    conn = get_db_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # =========================
        # 残り問題チェック（まずは難易度込みで探す）
        # =========================
        question = _fetch_next_question(cur, strict_difficulty=True)

        # 初回から0件になる場合は、難易度条件がDBとズレている可能性が高いので救済
        if not question and session.get("question_count", 0) == 0:
            question = _fetch_next_question(cur, strict_difficulty=False)

        if not question:
            total = session.get("question_count", 0)
            correct = session.get("correct_count", 0)

            #session.clear()

            return render_template(
                "question.html",
                finished=True,
                total=total,
                correct=correct,
                genre=genre_en,
                level=level
            )

        # 選択肢
        cur.execute("""
            SELECT id, choice_text, is_correct
            FROM quiz_choices
            WHERE question_id = %s
            ORDER BY id
        """, (question["id"],))
        choices = cur.fetchall()

    correct_choice_id = next(c["id"] for c in choices if c["is_correct"])

    return render_template(
        "question.html",
        finished=False,
        question={
            "id": question["id"],
            "number": session["question_count"] + 1,
            "question_text": question["question_text"],
            "correct_choice_id": correct_choice_id,
            "explanation": question["explanation"],
            "image_url": question["image_data"],
        },
        choices=choices,
        genre=genre_en,
        level=level
    )



@app.route("/debug-categories")
def debug_categories():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM quiz_categories;")
        rows = cur.fetchall()
    return str(rows)


@app.route("/db-test")
def db_test():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        result = cur.fetchone()
        cur.close()
        conn.close()
        if not result:
            return "DB 接続成功！<br>(version取得に失敗しました)"
        return f"DB 接続成功！<br>{result[0]}"
    except Exception as e:
        return f"DB 接続失敗 ❌<br>{e}"


# =============================
# 実行
# =============================
if __name__ == "__main__":
    app.run(debug=True, port=8000)
