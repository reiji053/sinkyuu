# sinkyuu — Setup

## セットアップ (macOS / zsh)

1. Python 仮想環境を作成して有効化:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. 依存関係をインストール:

```bash
pip install -r requirements.txt
```

3. 環境変数を設定:

```bash
# 既に `.env` が存在する場合はそのまま編集してください
# 例: nano で編集
nano .env
# .env を編集して NEON_DATABASE_URL を設定してください
```

例: `NEON_DATABASE_URL=postgresql://user:pass@host:5432/dbname?sslmode=require`

4. アプリを起動:

```bash
python app.py
```

5. ブラウザで `http://localhost:5000/` にアクセスすると、DB の現在時刻が返ります。

---

## Git にあげる手順

※ `.env` のような機密情報は必ず `.gitignore` に含めてください（このリポジトリには `.gitignore` が含まれています）。

### 新規リポジトリとして作る場合

```bash
git init
git add .gitignore
git add -A
git commit -m "Initial commit"
git branch -M main
# origin の URL はご自身のリポジトリに置き換えてください
git remote add origin git@github.com:<your-username>/<your-repo>.git
git push -u origin main
```

### 既存リポジトリに反映する場合（リモートがある想定）

```bash
git pull --rebase origin main
git add .gitignore
git add -A
git commit -m "Update project files"
git push origin main
```

### 補足
- `.env` や API キーなどの機密情報は絶対にコミットしないでください。
- もし機密情報を誤ってコミットした場合は、`git filter-repo` 等で履歴から除去するか、該当のキーをローテーションしてください。
# sinkyuu — Setup

## セットアップ (macOS / zsh)

1. Python 仮想環境を作成して有効化:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. 依存関係をインストール:

```bash
pip install -r requirements.txt
```

3. 環境変数を設定:

```bash
# 既に `.env` が存在する場合はそのまま編集してください
# 例: nano で編集
nano .env
# .env を編集して NEON_DATABASE_URL を設定してください
```

例: `NEON_DATABASE_URL=postgresql://user:pass@host:5432/dbname?sslmode=require`

4. アプリを起動:

```bash
python app.py
```

5. ブラウザで `http://localhost:5000/` にアクセスすると、DB の現在時刻が返ります。
