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

load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "dev-secret-key"


# DB接続先（PostgreSQL）
def database_url() -> str | None:
    return os.environ.get("DATABASE_URL")


# pgのsslmodeは環境差が大きいので、最低限の自動判定を入れている
def _select_pg_sslmode(db_url: str) -> str:
    sslmode = os.environ.get("PGSSLMODE")
    if sslmode:
        return sslmode

    # ローカルの Postgres は SSL 無効なことが多いので推測する（本番は require を既定）
    if "localhost" in db_url or "127.0.0.1" in db_url:
        return "disable"
    return "require"


# デプロイ環境判定（CookieのSecureやdebug切替に使う）
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


# フォームPOST用のCSRFトークン（セッションに保持）
def csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


# セッション内トークンとフォームのトークンが一致するか
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


# ログイン試行の簡易レート制限（IP単位）
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
    if not database_url():
        raise RuntimeError(
            "DATABASE_URL が未設定です。.env に DATABASE_URL=... を設定するか、環境変数で指定してください。"
        )

# =============================
# DB 接続関数
# =============================
def get_db():
    require_database_url()
    db_url = database_url() or ""
    return psycopg2.connect(
        db_url,
        sslmode=_select_pg_sslmode(db_url),
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

    # データ正規化（emailは小文字、nameは空文字を空文字のまま維持）
    cur.execute(
        """
        UPDATE users
        SET email = LOWER(email)
        WHERE email IS NOT NULL AND email <> LOWER(email)
        """
    )
    cur.execute(
        """
        UPDATE users
        SET name = CASE
            WHEN BTRIM(name) = '' THEN ''
            ELSE name
        END
        """
    )

    # name（ユーザーネーム）を入力しているユーザー同士で重複がある場合は、
    # 既存データを壊さない範囲で後続のみサフィックス付与して一意化する。
    cur.execute(
        """
        WITH ranked AS (
            SELECT id,
                   name,
                   ROW_NUMBER() OVER (PARTITION BY LOWER(name) ORDER BY id) AS rn
            FROM users
            WHERE name IS NOT NULL AND name <> ''
        )
        UPDATE users u
        SET name = u.name || '_' || u.id
        FROM ranked r
        WHERE u.id = r.id AND r.rn > 1
        """
    )

    # 一般的な運用に寄せるため、ケース非依存の一意性をDBでも保証する（email/name）
    # 既存DBが壊れていて作れない場合でもアプリ側チェックでカバーする。
    try:
        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique_idx
            ON users (LOWER(email))
            """
        )
    except Exception as e:
        print(f"[WARN] users_email_lower_unique_idx を作成できませんでした: {e}")

    try:
        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS users_name_lower_unique_idx
            ON users (LOWER(name))
            WHERE name IS NOT NULL AND name <> ''
            """
        )
    except Exception as e:
        print(f"[WARN] users_name_lower_unique_idx を作成できませんでした: {e}")

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

    # ユーザーの学習統計（Achievement 判定用）
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_stats (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            total_questions INTEGER NOT NULL DEFAULT 0,
            total_correct INTEGER NOT NULL DEFAULT 0,
            total_score INTEGER NOT NULL DEFAULT 0,
            quizzes_completed INTEGER NOT NULL DEFAULT 0,
            current_streak INTEGER NOT NULL DEFAULT 0,
            last_study_date DATE,
            updated_at TIMESTAMP DEFAULT NOW()
        )
        """
    )

    conn.commit()
    cur.close()
    conn.close()

# import時にテーブル作成/補完まで済ませておく（ローカル開発向け）
# 本番環境で毎回DDLを流すと遅延/ロック/負荷の原因になるため実行しない。
if database_url() and not IS_PRODUCTION:
    init_db()
elif not database_url():
    print("[WARN] DATABASE_URL が未設定のため DB 初期化をスキップします")


# ログイン用パスワード検証（新形式/旧形式の両対応）
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


# ログインに必要な最小情報だけ取る（存在確認 + hash）
def fetch_user_for_login(cur, identifier: str):
    identifier = (identifier or "").strip()
    if not identifier:
        return None

    # ログインはメールアドレス必須（一般的な運用に合わせる）
    cur.execute(
        "SELECT id, password_hash FROM users WHERE LOWER(email) = LOWER(%s)",
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
        identifier = (request.form.get("email") or "").strip()
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
# get_db() と違い、こちらはアプリ内の大半の処理で使う素の接続
def get_db_connection():
    require_database_url()
    db_url = database_url() or ""
    return psycopg2.connect(db_url, sslmode=_select_pg_sslmode(db_url))

@app.route("/signup-email", methods=["GET", "POST"])
def signup_email():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            name = ""
        email = (request.form.get("email") or "").strip().lower()
        password = request.form["password"]

        if not email:
            flash("Email is required.")
            return redirect(url_for("signup_email"))

        if name:
            # ユーザーネームを使うなら重複禁止（ケース非依存）
            conn_tmp = get_db_connection()
            try:
                with conn_tmp.cursor(cursor_factory=RealDictCursor) as cur_tmp:
                    cur_tmp.execute(
                        "SELECT 1 FROM users WHERE LOWER(name) = LOWER(%s) LIMIT 1",
                        (name,),
                    )
                    if cur_tmp.fetchone():
                        flash("This username is already taken.")
                        return redirect(url_for("signup_email"))
            finally:
                conn_tmp.close()

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
# GETでログアウトできるとCSRFで踏まれやすいので、POST専用にしている
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return redirect("/signin")

# =============================
# 選択・問題画面
# =============================
@app.route("/difficulty")
def difficulty():
    genre = (request.args.get("genre") or "").strip()
    if not genre:
        return redirect("/select")
    return render_template("difficulty.html", genre=genre)

@app.route("/frequency")
def frequency():
    return render_template("frequency.html")

@app.route("/ready")
def ready():
    return render_template("ready.html")

@app.route("/select")
def select():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")
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


def _ensure_user_stats_table(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_stats (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            total_questions INTEGER NOT NULL DEFAULT 0,
            total_correct INTEGER NOT NULL DEFAULT 0,
            total_score INTEGER NOT NULL DEFAULT 0,
            quizzes_completed INTEGER NOT NULL DEFAULT 0,
            current_streak INTEGER NOT NULL DEFAULT 0,
            last_study_date DATE,
            updated_at TIMESTAMP DEFAULT NOW()
        )
        """
    )


def _ensure_user_stats_row(cur, user_id: int) -> None:
    _ensure_user_stats_table(cur)
    cur.execute(
        """
        INSERT INTO user_stats (user_id)
        VALUES (%s)
        ON CONFLICT (user_id) DO NOTHING
        """,
        (user_id,),
    )


def _ensure_user_category_stats_table(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_category_stats (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            genre TEXT NOT NULL,
            total_questions INTEGER NOT NULL DEFAULT 0,
            total_correct INTEGER NOT NULL DEFAULT 0,
            total_score INTEGER NOT NULL DEFAULT 0,
            quizzes_completed INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT NOW(),
            PRIMARY KEY (user_id, genre)
        )
        """
    )


def _ensure_user_category_stats_row(cur, user_id: int, genre: str) -> None:
    _ensure_user_category_stats_table(cur)
    cur.execute(
        """
        INSERT INTO user_category_stats (user_id, genre)
        VALUES (%s, %s)
        ON CONFLICT (user_id, genre) DO NOTHING
        """,
        (user_id, genre),
    )


def _get_app_language() -> str:
    # settings_language でセットされる値に合わせる
    return session.get("app_language") or "English"


def _pick_localized(row: dict, base_key: str) -> str | None:
    lang = _get_app_language()
    if lang == "Hindi":
        return row.get(f"{base_key}_hi") or row.get(base_key)
    if lang == "Japanese":
        return row.get(base_key)
    # English / default
    return row.get(f"{base_key}_en") or row.get(base_key)


def _update_user_stats_on_answer(*, user_id: int, is_correct: bool, genre: str | None = None) -> None:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            _ensure_user_stats_row(cur, user_id)

            score_delta = 1 if is_correct else 0
            cur.execute(
                """
                UPDATE user_stats
                SET
                    total_questions = total_questions + 1,
                    total_correct = total_correct + %s,
                    total_score = total_score + %s,
                    updated_at = NOW()
                WHERE user_id = %s
                """,
                (1 if is_correct else 0, score_delta, user_id),
            )

            genre_key = (genre or "").strip()
            if genre_key and genre_key.lower() != "shuffle":
                _ensure_user_category_stats_row(cur, user_id, genre_key)
                cur.execute(
                    """
                    UPDATE user_category_stats
                    SET
                        total_questions = total_questions + 1,
                        total_correct = total_correct + %s,
                        total_score = total_score + %s,
                        updated_at = NOW()
                    WHERE user_id = %s AND genre = %s
                    """,
                    (1 if is_correct else 0, score_delta, user_id, genre_key),
                )

        conn.commit()
    finally:
        conn.close()


def _record_quiz_completed(*, user_id: int, genre: str | None = None) -> None:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            _ensure_user_stats_row(cur, user_id)
            cur.execute(
                """
                UPDATE user_stats
                SET quizzes_completed = quizzes_completed + 1, updated_at = NOW()
                WHERE user_id = %s
                """,
                (user_id,),
            )

            genre_key = (genre or "").strip()
            if genre_key and genre_key.lower() != "shuffle":
                _ensure_user_category_stats_row(cur, user_id, genre_key)
                cur.execute(
                    """
                    UPDATE user_category_stats
                    SET quizzes_completed = quizzes_completed + 1, updated_at = NOW()
                    WHERE user_id = %s AND genre = %s
                    """,
                    (user_id, genre_key),
                )
        conn.commit()
    finally:
        conn.close()


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            name = ""
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email:
            flash("Email is required.")
            return redirect("/profile")

        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
                if not cur.fetchone():
                    session.pop("user_id", None)
                    conn.commit()
                    return redirect("/signin")

                fields = ["name = %s", "email = %s", "updated_at = NOW()"]
                params: list[object] = [name, email]

                if password.strip():
                    fields.insert(2, "password_hash = %s")
                    params.insert(2, generate_password_hash(password))

                params.append(user_id)
                cur.execute(
                    f"UPDATE users SET {', '.join(fields)} WHERE id = %s",
                    tuple(params),
                )

            conn.commit()

        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash("This email is already registered.")
        finally:
            conn.close()

        return redirect("/profile")

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, email, name FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                session.pop("user_id", None)
                conn.commit()
                return redirect("/signin")

        conn.commit()
    finally:
        conn.close()

    return render_template(
        "profile.html",
        user=user,
    )


@app.route("/achievements")
def achievements():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, email, name FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                session.pop("user_id", None)
                conn.commit()
                return redirect("/signin")

            achievements_view, _mode, stats_view = _build_achievements_view(cur, user_id=int(user_id))

        conn.commit()
    finally:
        conn.close()

    return render_template(
        "achievements.html",
        user=user,
        achievements=achievements_view,
        stats=stats_view,
    )


def _build_achievements_view(cur, *, user_id: int):
    """Return (achievements_view, mode, stats_dict)"""
    # user_stats（Achievement 判定用）
    _ensure_user_stats_row(cur, int(user_id))
    cur.execute(
        """
        SELECT
            total_questions,
            total_correct,
            total_score,
            quizzes_completed
        FROM user_stats
        WHERE user_id = %s
        """,
        (user_id,),
    )
    stats = cur.fetchone() or {}

    total_questions = int(stats.get("total_questions") or 0)
    total_correct = int(stats.get("total_correct") or 0)
    total_score = int(stats.get("total_score") or 0)
    quizzes_completed = int(stats.get("quizzes_completed") or 0)
    accuracy = (total_correct * 100.0 / total_questions) if total_questions > 0 else 0.0

    stats_view = {
        "total_questions": total_questions,
        "total_correct": total_correct,
        "total_score": total_score,
        "quizzes_completed": quizzes_completed,
        "accuracy": round(accuracy, 1),
    }

    # genre別の統計（カテゴリ実績用）
    cur.execute(
        """
        SELECT genre, total_questions, total_correct, total_score, quizzes_completed
        FROM user_category_stats
        WHERE user_id = %s
        """,
        (user_id,),
    )
    category_rows = cur.fetchall() or []
    category_stats: dict[str, dict] = {r.get("genre"): r for r in category_rows if r.get("genre")}

    # achievements テーブルがあるならそれを表示（無い場合は旧バッジをフォールバック）
    cur.execute("SELECT to_regclass('public.achievements') AS t")
    has_achievements = bool((cur.fetchone() or {}).get("t"))

    achievements_view = []
    if has_achievements:
        cur.execute(
            """
            SELECT
                id,
                name,
                name_en,
                name_hi,
                description,
                description_en,
                description_hi,
                achievement_type,
                condition_value,
                badge_image,
                badge_color,
                display_order
            FROM achievements
            ORDER BY display_order NULLS LAST, id
            """
        )
        rows = cur.fetchall() or []

        for r in rows:
            a_type = (r.get("achievement_type") or "").strip()
            cond = int(r.get("condition_value") or 0)

            # day_streak（streak）機能は廃止
            if a_type in {"streak", "day_streak"}:
                continue

            earned = False
            if not a_type:
                # 既存DBに achievement_type が入っていない場合の救済。
                # 例: レジ対応銅/銀/金バッチ はカテゴリ（genre）別のクイズ完了回数で判定する。
                raw_name = (r.get("name") or "").strip()
                prefix_to_genre = {
                    "レジ対応": "Cashier Service",
                    "品出し": "Conversation during Stocking",
                    "クレーム対応": "Handling Complaints",
                }
                metal_to_threshold = {
                    "銅": 1,
                    "銀": 3,
                    "金": 5,
                }

                matched_genre = None
                matched_threshold = None
                for prefix, genre_key in prefix_to_genre.items():
                    if raw_name.startswith(prefix):
                        matched_genre = genre_key
                        break

                if matched_genre:
                    for metal, threshold in metal_to_threshold.items():
                        if metal in raw_name:
                            matched_threshold = threshold
                            break

                if matched_genre and matched_threshold:
                    row_stats = category_stats.get(matched_genre) or {}
                    g_quizzes_completed = int(row_stats.get("quizzes_completed") or 0)
                    effective_cond = cond if cond > 0 else int(matched_threshold)
                    earned = g_quizzes_completed >= effective_cond
                    a_type = "genre_quiz_completed"
                    cond = effective_cond

                # 総合（全カテゴリ合算）は全体のquizzes_completedで判定
                if raw_name.startswith("総合"):
                    matched_threshold = None
                    for metal, threshold in metal_to_threshold.items():
                        if metal in raw_name:
                            matched_threshold = threshold
                            break
                    if matched_threshold:
                        effective_cond = cond if cond > 0 else int(matched_threshold)
                        earned = quizzes_completed >= effective_cond
                        a_type = "quiz_completed"
                        cond = effective_cond

            if a_type == "quiz_completed":
                earned = quizzes_completed >= cond
            elif a_type == "accuracy":
                earned = total_questions > 0 and accuracy >= float(cond)
            elif a_type == "total_score":
                earned = total_score >= cond

            achievements_view.append(
                {
                    "id": r.get("id"),
                    "name": _pick_localized(r, "name") or "",
                    "description": _pick_localized(r, "description") or "",
                    "achievement_type": a_type,
                    "condition_value": cond,
                    "badge_image": r.get("badge_image"),
                    "badge_color": r.get("badge_color"),
                    "earned": earned,
                }
            )

        return achievements_view, "achievements", stats_view

    # 旧バッジ（既存のDBでも落ちないように）
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
    cur.execute(
        """
        SELECT
            NULL::INTEGER AS id,
            b.name,
            COALESCE(b.description, '') AS description,
            NULL::TEXT AS achievement_type,
            0::INTEGER AS condition_value,
            NULL::TEXT AS badge_image,
            NULL::TEXT AS badge_color,
            (ub.user_id IS NOT NULL) AS earned
        FROM badges b
        LEFT JOIN user_badges ub
            ON ub.badge_id = b.id AND ub.user_id = %s
        ORDER BY b.id
        """,
        (user_id,),
    )
    return (cur.fetchall() or []), "badges", stats_view


@app.route("/debug/achievements")
def debug_achievements():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, email, name FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                session.pop("user_id", None)
                conn.commit()
                return redirect("/signin")

            achievements_view, mode, stats_view = _build_achievements_view(cur, user_id=int(user_id))
        conn.commit()
    finally:
        conn.close()

    return render_template(
        "debug_achievements.html",
        user=user,
        achievements=achievements_view,
        mode=mode,
        stats=stats_view,
    )


@app.route("/account")
def account():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/signin")

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, email, name FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                session.pop("user_id", None)
                conn.commit()
                return redirect("/signin")
            _ensure_user_stats_row(cur, int(user_id))
            cur.execute("SELECT total_score FROM user_stats WHERE user_id = %s", (user_id,))
            points_row = cur.fetchone() or {}
            points = int(points_row.get("total_score") or 0)
        conn.commit()
    finally:
        conn.close()

    return render_template("account.html", user=user, points=points)


@app.route("/settings")
def settings():
    # 旧導線の名残。今は設定をselect側に寄せている。
    return redirect("/select")


@app.route("/settings/language", methods=["GET", "POST"])
def settings_language():
    # UI上は雰囲気だけ残し、実処理はselect側に寄せる（現状は未実装）
    return redirect("/select")


@app.route("/settings/help")
def settings_help():
    return render_template("settings_stub.html", title="Help / FAQ")


@app.route("/settings/feedback")
def settings_feedback():
    return render_template("settings_stub.html", title="Feedback")


@app.route("/settings/terms")
def settings_terms():
    return render_template("settings_stub.html", title="Terms of Service")


@app.route("/settings/privacy")
def settings_privacy():
    return render_template("settings_stub.html", title="Privacy Policy")

@app.route("/question", methods=["GET", "POST"])
def question():
    user_id = session.get("user_id")
    if not user_id:

        #testt
        return redirect("/signin")
    # クイズ出題のメイン。
    # セッションに「出題済みID」「回答数」「正答数」を持ち、DBには統計だけ反映する。
    genre_en = (request.args.get("genre") or "").strip()
    level = request.args.get("level")
    reset = request.args.get("reset")

    if not genre_en or not level:
        return "パラメータが不足しています"

    is_shuffle = genre_en.lower() == "shuffle"

    # Shuffle はカテゴリ指定なしで出題
    genre_filter = None if is_shuffle else genre_en

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
        session["quiz_completion_recorded"] = False

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

        # ログイン済みならDBへ学習統計を反映（Achievement判定に使う）
        uid = session.get("user_id")
        if uid:
            _update_user_stats_on_answer(user_id=int(uid), is_correct=(is_correct == "1"), genre=genre_en)

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

        order_by = "RANDOM()" if is_shuffle else "q.id"

        sql = f"""
            SELECT
                q.id,
                q.question_text,
                q.explanation,
                c.name AS category_name,
                ci.image_url
            FROM quiz_questions q
            JOIN quiz_categories c
                ON q.category_id = c.id
            LEFT JOIN category_images ci
                ON ci.category_id = c.id
            WHERE {' AND '.join(where_parts)}
            ORDER BY {order_by}
            LIMIT 1
        """
        cur.execute(sql, tuple(params))
        return cur.fetchone()

    conn = get_db_connection()
    try:
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

                uid = session.get("user_id")
                if uid and total > 0 and not session.get("quiz_completion_recorded"):
                    _record_quiz_completed(user_id=int(uid), genre=genre_en)
                    session["quiz_completion_recorded"] = True

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

            # 正解・不正解用画像（base64）
            correct_image = None
            wrong_image = None
            cur.execute("SELECT image_url FROM images WHERE id = 2")
            row = cur.fetchone()
            if row:
                correct_image = row["image_url"]
            cur.execute("SELECT image_url FROM images WHERE id = 3")
            row = cur.fetchone()
            if row:
                wrong_image = row["image_url"]
    finally:
        conn.close()

    # choicesの中に正解が1つある前提（DBデータが壊れていると例外になる）
    correct_choice_id = next(c["id"] for c in choices if c["is_correct"])

    image_url = question["image_url"]

    if image_url:
        image_url = (
            image_url
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")
        )


    return render_template(
        "question.html",
        finished=False,
        question={
            "id": question["id"],
            "number": session["question_count"] + 1,
            "question_text": question["question_text"],
            "correct_choice_id": correct_choice_id,
            "explanation": question["explanation"],
            "image_url": image_url,
        },
        choices=choices,
        genre=genre_en,
        level=level,
        correct_image=correct_image,
        wrong_image=wrong_image,
    )



@app.route("/debug-categories")
def debug_categories():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM quiz_categories;")
        rows = cur.fetchall()
    return str(rows)

# =============================
# 実行
# =============================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=not IS_PRODUCTION)

# test