## 1. 全体像（このファイルの役割）

メモ: VS Code の Markdown プレビューは、GitHub 形式の `#L123` のような行アンカーにジャンプしない。
そのためこの資料では、リンクはファイルを開く用途にとどめ、行番号は表示テキストとして併記している。
最短で該当行へ飛ぶには `Cmd+P` → `app.py:123`（例: `app.py:1175`）の形式で開くとよい。

[app.py](app.py) は Flask アプリのエントリポイントであり、主に次を1ファイルで担当する。

- Flask アプリ生成・本番/開発の切替（Cookie設定、debug設定など）
- DB（PostgreSQL）への接続と初期化（テーブル作成、古いDBへの補完、正規化）
- 認証（サインアップ/サインイン/ログアウト）、CSRF保護、ログイン試行の簡易レート制限
- パスワードリセット（トークン発行と更新）
- クイズ出題（セッションで状態管理しつつ、統計だけDBへ反映）
- Achievements（DBに achievements テーブルがある場合はそれ、無い場合は badges を使うフォールバック）
- Account/Profile(Settingsの一部)画面の表示

該当コード:
- dotenv読み込み: [app.py（L21）](app.py)
- sslmode推測: [app.py（L33）](app.py)
- 本番判定: [app.py（L45）](app.py)
- CSRF: [app.py（L69）](app.py) / [app.py（L91）](app.py)
- DB初期化: [app.py（L162）](app.py)
- 認証（/signup, /signin, /logout）: [app.py（L372）](app.py) / [app.py（L409）](app.py) / [app.py（L706）](app.py)
- Profile: [app.py（L856）](app.py)
- Quiz: [app.py（L1175）](app.py)
- Achievements: [app.py（L925）](app.py)


---

## 2. 起動時に行われること

### 2.1 [.env](.env) の読み込み

- `load_dotenv(override=True)` により [.env](.env) を読み込む。

該当コード: [app.py（L21）](app.py)

### 2.2 本番判定 → Cookie設定

- `_is_production()` で本番かどうかを判定する。
- 判定結果 `IS_PRODUCTION` に応じて、セッションCookieが次のように設定される。
  - `SESSION_COOKIE_HTTPONLY=True`（JavaScript からCookieを読めない）
  - `SESSION_COOKIE_SAMESITE="Lax"`（CSRF低減）
  - `SESSION_COOKIE_SECURE=IS_PRODUCTION`（本番はHTTPS前提で Secure）

さらに、本番なのに `FLASK_SECRET_KEY` が未設定（`dev-secret-key` のまま）の場合は例外で停止する。

該当コード:
- 本番判定: [app.py（L45）](app.py)

### 2.3 DB初期化（DATABASE_URL がある場合）

- `DATABASE_URL` があると、import時に `init_db()` が実行される。
- ここでは以下が行われる。
  - `users` / `badges` / `user_badges` / `password_reset_tokens` / `user_stats` テーブルを作成
  - `users` テーブルに不足カラムがあれば追加（古いDBでも落ちないように）
  - 旧カラム `password` が残っていたら `password_hash` へ移行
  - `email` を小文字に正規化
  - `name` の重複を「壊さない範囲で」後続だけサフィックスを付けて一意化（例: `foo` が2件なら後ろの方を `foo_123` のように）
  - `email` と `name` について、DB側でも大文字小文字を無視して一意になるよう UNIQUE INDEX を作成（作れない場合は WARN を出して続行）

注意: import時にDBへアクセスするため、`DATABASE_URL` が不正だと起動段階で失敗する。

該当コード:
- DB初期化関数: [app.py（L162）](app.py)

---

## 3. セキュリティ系の共通処理

### 3.1 CSRF

- `csrf_token()` がセッションに `_csrf_token` を生成して保持する。
- `@app.before_request` の `_csrf_protect()` が、`POST/PUT/PATCH/DELETE` のたびに `_validate_csrf()` を実行する。
  - `request.endpoint == "static"` は除外
  - `session["_csrf_token"]` と `form["_csrf_token"]` が両方あり、かつ一致しないと `400` で落とす

このため、フォーム送信はテンプレ側で `csrf_token()` を埋め込む前提である。

該当コード:
- トークン生成（テンプレから参照）: [app.py（L69）](app.py)
- 検証とbefore_request: [app.py（L91）](app.py)

### 3.2 ログイン試行の簡易レート制限

- `_LOGIN_ATTEMPTS` に、キー（例: `signin:IP`）ごとの時刻リストを持つ。
- `_is_rate_limited()` が「一定時間内の試行回数が `limit` を超えたか」を判定する。
- サインイン成功時は `_clear_attempts()`、失敗時は `_record_attempt()` で追加する。

該当コード:
- 試行履歴: [app.py（L100）](app.py)
- 判定: [app.py（L110）](app.py)
- 記録: [app.py（L124）](app.py)
- クリア: [app.py（L137）](app.py)

---

## 4. DB接続まわり

- `database_url()` は `DATABASE_URL` を返すだけの薄い関数である。
- `require_database_url()` は未設定なら例外にする。
- `_select_pg_sslmode()` はローカル（localhost/127.0.0.1）なら `disable`、それ以外は `require` を基本にしつつ、`PGSSLMODE` があればそれを優先する。
- `get_db()` は `cursor_factory=DictCursor` を付けた接続を返す。
- `get_db_connection()` はアプリ内で主に使われる接続関数で、`sslmode` だけ指定した素の接続を返す。

※ 現状 `get_db()` と `get_db_connection()` が共存しており、実際のルートは `get_db_connection()` を多用している。

該当コード:
- sslmode推測: [app.py（L33）](app.py)
- DATABASE_URL必須チェック: [app.py（L141）](app.py)
- 接続（DictCursor）: [app.py（L150）](app.py)
- 接続（素の接続）: [app.py（L443）](app.py)

---

## 5. 認証（signup / signin / logout）

### 5.1 パスワード検証

`verify_password(stored_hash, password)` は、DBの `password_hash` が以下のどれでも動くようにしている。

- werkzeug形式（例: `pbkdf2:sha256:...`）→ `check_password_hash()`
- 旧形式として 32桁hex（MD5想定）→ 入力パスワードのMD5と比較

該当コード: [app.py（L331）](app.py)

### 5.2 サインアップ

- `GET /signup` は [templates/signup.html](templates/signup.html) を返す。
- `POST /signup` も一応実装されている（既存テンプレがPOSTしない前提の保険）。
  - email/password が無ければ `400`
  - `password_hash` を作って `users` へ INSERT
  - 既に同じemailがあれば UniqueViolation を拾ってメッセージ
  - 完了後 `/signin` へ

該当コード: [app.py（L372）](app.py)

### 5.3 サインイン

- `GET /signin` は [templates/signin.html](templates/signin.html) を返す。
- `POST /signin`
  - IPベースのレート制限をチェック
  - `fetch_user_for_login()` で `users` から該当emailの `id/password_hash` を取る
  - `verify_password()` に通れば `session["user_id"]` をセット
  - `last_login_at` と `updated_at` を更新して `/select` へリダイレクト
  - 失敗時は試行回数を記録してエラーメッセージ

該当コード:
- ルート: [app.py（L409）](app.py)
- ログイン用ユーザー取得: [app.py（L350）](app.py)

### 5.4 signup_email / signin_email

別テンプレ [templates/signup_email.html](templates/signup_email.html) 用の導線がある。
- `POST /signup-email` は name/email/password を受け取り、必要なチェック後に `users` を作ってログイン状態にする。
- name が入っている場合だけ「ケース非依存で重複禁止」のチェックを入れている。

該当コード:
- signup-email: [app.py（L448）](app.py)
- signin-email: [app.py（L529）](app.py)

### 5.5 ログアウト

- `POST /logout` で `session["user_id"]` を消して `/signin` へ遷移させる。
- GET を許可していないため、URL踏みでログアウトされるパターン（CSRF）を避ける。

該当コード: [app.py（L706）](app.py)

---

## 6. パスワードリセット（/forgot, /reset-password）

### 6.1 /forgot

- `GET /forgot` は入力画面（[templates/forgot.html](templates/forgot.html)）を返す。
- `POST /forgot` はメール送信の代わりに「開発用としてリセットURLを flash で表示」する。
  - 存在するユーザーなら `password_reset_tokens` にトークン（sha256ハッシュ）と有効期限（1時間）を保存
  - 存在しないメールでも同じようなメッセージを返してユーザー有無を漏らしにくくしている

該当コード: [app.py（L560）](app.py)

### 6.2 /reset-password

- `GET /reset-password?token=...` はフォーム表示である。
- `POST /reset-password`
  - token を sha256 してDBを検索
  - 期限切れ/使用済み/存在しない場合はメッセージを出して戻す
  - OKなら `users.password_hash` を更新し、トークンに `used_at` を入れて無効化

該当コード: [app.py（L616）](app.py)

---

## 7. Account / Profile / Settings

### 7.1 /account

- `session["user_id"]` が無ければ `/signin`
- `users` から user を読み、`user_stats` から `total_score` を points として取得する。
  - `user_stats` が無い場合も落ちないように、先に `_ensure_user_stats_row()` を呼ぶ。
- [templates/account.html](templates/account.html) を `user` と `points` 付きで表示する。

該当コード:
- ルート: [app.py（L1118）](app.py)
- user_stats行の確保: [app.py（L786）](app.py)

### 7.2 /profile

- `session["user_id"]` が無ければ `/signin`
- `GET /profile` は DB から `id/email/name` を取って [templates/profile.html](templates/profile.html) を表示する。
- `POST /profile` は name/email/password（任意）を更新する。
  - password が空なら `password_hash` は更新しない
  - email が空なら flash して戻す
  - email重複は UniqueViolation で拾って flash

該当コード: [app.py（L856）](app.py)


---

## 8. クイズ機能（/question まわり）

### 8.1 入口とパラメータ

- `GET /question?genre=...&level=...` が基本である。
  - `genre` または `level` が無いとエラーを返す
- `genre=shuffle` の場合はカテゴリ固定せずランダム出題する。
- `reset=1` の場合は「クイズ状態だけ」消したいため、`user_id` とCSRFだけ残して `session.clear()` する。

該当コード: [app.py（L1175）](app.py)

### 8.2 セッションで持つ状態

初回アクセス時に以下を作る。

- `used_question_ids`: 出題済みIDの配列
- `question_count`: 何問回答したか
- `correct_count`: 何問正解したか
- `quiz_completion_recorded`: 終了時にDBへ「クイズ完了」を記録したか（重複防止）

### 8.3 POST（Next）時の動き

`POST /question` は、テンプレから送られてきた `question_id` と `is_correct` を受け取る。

- `used_question_ids` に `question_id` を追加する。
- `question_count` を +1 する。
- `is_correct=="1"` なら `correct_count` を +1 する。
- ログイン済み（`session["user_id"]` あり）なら、DBの `user_stats` を更新する。
- 次の問題を出すために `GET /question` へリダイレクトする。


該当コード:
- POST処理（回答の反映）: [app.py（L1223）](app.py)
- 統計更新: [app.py（L813）](app.py)

### 8.4 次の問題の取り方（GET）

- `_fetch_next_question(strict_difficulty=True)` で「未出題」「カテゴリ一致（shuffle以外）」「難易度一致」を満たす次の問題を1件取得する。
  - shuffle の場合は `ORDER BY RANDOM()`
  - shuffle 以外は `ORDER BY q.id`
- もし「最初の1問目から0件」なら、難易度条件がDBと噛み合ってない救済として `strict_difficulty=False` でもう一度探す。

該当コード（次問取得）: [app.py（L1243）](app.py)

### 8.5 終了時

次の問題が取れなかったら終了扱いで、

- `total/correct` をテンプレへ渡して [templates/question.html](templates/question.html) を `finished=True` で表示する。
- ログイン済みで、かつ `total > 0` で、まだ未記録なら `_record_quiz_completed()` を呼ぶ。

該当コード:
- 終了判定（問題が無い場合の処理）: [app.py（L1287）](app.py)
- クイズ完了の記録: [app.py（L838）](app.py)

### 8.6 選択肢の読み込み

- `quiz_choices` から `question_id` の選択肢を取得する。
- `choices` の中から `is_correct` の行を探して `correct_choice_id` を作る。
  - DB側に正解が1つある前提で、無い場合は例外になる。

該当コード: [app.py（L1311）](app.py)

### 8.7 画像URLの扱い

- `category_images` の `image_url` を取り、改行や空白を取り除いて `image_url` としてテンプレへ渡す。

該当コード: [app.py（L1320）](app.py)

---

## 9. Achievements（/achievements と関連）

### 9.1 統計の下準備

- `_ensure_user_stats_row()` で user_stats に行が無ければ作る。
- `_update_user_stats_on_answer()` は回答ごとに `total_questions/total_correct/total_score` を更新する。
- `_record_quiz_completed()` はクイズ完了時に `quizzes_completed` を +1 する。

加えて、カテゴリ（ジャンル）別の実績判定のために `user_category_stats` も使う。

- `_update_user_stats_on_answer(..., genre=...)` で、ログイン済みかつ `genre != Shuffle` のとき、
  `user_category_stats` の `total_questions/total_correct/total_score` も更新する。
- `_record_quiz_completed(..., genre=...)` で、ログイン済みかつ `genre != Shuffle` のとき、
  `user_category_stats` の `quizzes_completed` も +1 する。

該当コード:
- user_stats行の確保: [app.py（L786）](app.py)
- genre別statsテーブル作成: [app.py（L798）](app.py)
- 回答時の統計更新: [app.py（L842）](app.py)
- クイズ完了の記録: [app.py（L883）](app.py)

### 9.2 表示モードの分岐

`_build_achievements_view()` は、DBに `achievements` テーブルがあるかを見て挙動を切り替える。

- ある場合
  - achievements を `display_order` で並べ、条件（quiz_completed/accuracy/total_score）に応じて `earned` を計算
  - `streak` 系の achievement_type は廃止扱いでスキップ
- 無い場合
  - `badges` と `user_badges` を作成し、最低限のデフォルトバッジを入れて表示する

該当コード:
- Achievementsルート: [app.py（L982）](app.py)
- 表示データ生成: [app.py（L1012）](app.py)

### 9.3 実績（バッチ）条件

achievements テーブルの `achievement_type` による条件は次の通りである。

- `quiz_completed`
  - 判定: `user_stats.quizzes_completed >= condition_value`
- `accuracy`
  - 判定: `user_stats.total_questions > 0` かつ `accuracy >= condition_value`
  - accuracy は $\frac{total\_correct}{total\_questions}\times 100$（%）で計算する。
- `total_score`
  - 判定: `user_stats.total_score >= condition_value`

また、既存DBで `achievement_type` が空（空文字）になっている実績データがあるため、名前から条件を推定する救済ロジックがある。

- カテゴリ別（レジ対応/品出し/クレーム対応）
  - 対象: `name` が `レジ対応` / `品出し` / `クレーム対応` で始まるもの
  - 判定: `user_category_stats.quizzes_completed >= しきい値`
  - しきい値（名前に含まれる文字で決める）
    - 銅: 1回
    - 銀: 3回
    - 金: 5回
  - ジャンルの対応（select画面の英語ラベルに合わせる）
    - `レジ対応` → `Cashier Service`
    - `品出し` → `Conversation during Stocking`
    - `クレーム対応` → `Handling Complaints`
  - `Shuffle` はカテゴリが混ざるため、genre別のカウント対象外である。

- 総合（総合銅/銀/金）
  - 対象: `name` が `総合` で始まるもの
  - 判定: `user_stats.quizzes_completed >= しきい値`（銅=1 / 銀=3 / 金=5）

備考:
- `condition_value` が正の値で入っている場合は、その値を優先して判定する（DBで条件を管理できるようにするため）。
- 実績の中身（`achievement_type` や `condition_value`）は [app.py（L1206）](app.py) の `GET /debug/achievements` で確認できる。

---

## 10. ルート一覧（概要）

- `GET /` : タイトル（[templates/title.html](templates/title.html)）
- `GET/POST /signup` : サインアップ（基本はGET想定、POSTも保険で実装）
- `GET/POST /signin` : サインイン
- `GET/POST /signup-email` : メールサインアップ（別テンプレ用）
- `POST /signin-email` : メールサインイン（別テンプレ用）
- `GET/POST /forgot` : リセットURLを表示（開発用）
- `GET/POST /reset-password` : パスワード更新
- `POST /logout` : ログアウト
- `GET /select` : カテゴリ選択
- `GET /difficulty` : 難易度選択
- `GET /frequency` / `GET /ready` : 画面表示
- `GET/POST /question` : クイズ本体
- `GET /account` : Account画面
- `GET/POST /profile` : Profile編集
- `GET /achievements` : Achievements画面
- `GET /settings` : 現状は `/select` へ
- `GET/POST /settings/language` : 現状は `/select` へ
- `GET /settings/help|feedback|terms|privacy` : stubページ
- `GET /debug-categories` / `GET /debug/achievements` : デバッグ用

該当コード（主要ルートの開始行）:
- `/signup` : [app.py（L372）](app.py)
- `/signin` : [app.py（L409）](app.py)
- `/signup-email` : [app.py（L448）](app.py)
- `/signin-email` : [app.py（L529）](app.py)
- `/forgot` : [app.py（L560）](app.py)
- `/reset-password` : [app.py（L616）](app.py)
- `/logout` : [app.py（L706）](app.py)
- `/profile` : [app.py（L856）](app.py)
- `/achievements` : [app.py（L925）](app.py)
- `/account` : [app.py（L1118）](app.py)
- `/settings` : [app.py（L1144）](app.py)
- `/settings/help` : [app.py（L1156）](app.py)
- `/question` : [app.py（L1175）](app.py)



