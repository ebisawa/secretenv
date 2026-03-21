# secretenv ユーザーガイド

> このガイドは secretenv を初めて使うチームのために書かれた、自己完結型の日本語ドキュメントです。

---

## 目次

1. [はじめに](#1-はじめに)
2. [設計思想と運用哲学](#2-設計思想と運用哲学)
3. [コアコンセプト（用語解説）](#3-コアコンセプト用語解説)
4. [セキュリティモデル](#4-セキュリティモデル)
5. [インストール](#5-インストール)
6. [クイックスタート（チームリーダー向け）](#6-クイックスタートチームリーダー向け)
7. [新メンバーとして参加する](#7-新メンバーとして参加する)
8. [日常的な使い方（KV ストア）](#8-日常的な使い方kv-ストア)
9. [ファイルの暗号化・復号](#9-ファイルの暗号化復号)
10. [メンバー管理](#10-メンバー管理)
11. [鍵の管理とローテーション](#11-鍵の管理とローテーション)
12. [運用ガイドライン](#12-運用ガイドライン)
13. [よくある質問（FAQ）](#13-よくある質問faq)
14. [コマンドリファレンス（早見表）](#14-コマンドリファレンス早見表)

---

## 1. はじめに

### secretenv とは

チーム開発では、データベースのパスワード、API キー、証明書などの「秘密情報（secrets）」を複数のメンバーで共有する必要があります。しかし、その共有方法は往々にして問題をはらんでいます。

- Slack や Teams のチャットに平文でパスワードを貼り付けている
- `.env.example` に実際の値をコメントで残している
- 退職したメンバーが以前共有されたパスワードを知ったまま

secretenv はこうした問題を解決するための CLI ツールです。**暗号化された秘密情報を Git リポジトリで管理**することで、チームは安全かつ追跡可能な方法で secrets を共有できます。

### 何を解決するか

- `.env` や証明書ファイルを暗号化してリポジトリに格納し、チームで安全に共有できる
- メンバーの追加・削除に合わせて、暗号ファイルへのアクセス権を更新できる
- 誰がいつアクセスできたかの履歴を暗号ファイル自身が記録する
- サーバー不要・ネットワーク不要でオフラインでも動作する

### 何を解決しないか

secretenv には意図的に含めていない機能があります。過信を防ぐために明示します。

- **内部者の悪用防止**: 正当なメンバーとして参加し、復号した内容を悪用することは防げません
- **過去の開示の回収**: メンバーを削除しても、そのメンバーが過去に取得した値を無効化することはできません（詳細は [10章](#10-メンバー管理) を参照）
- **大規模 ACL 管理**: 「誰がどの secret を持つべきか」を定義する中央ポリシー機能はありません
- **鍵の漏洩対策**: ローカルの鍵ファイルが漏洩した場合の防御は OS レベルのセキュリティに依存します

---

## 2. 設計思想と運用哲学

### オフライン優先（Offline-First）

secretenv の全ての主要操作（暗号化・復号・署名検証・rewrap）はネットワーク接続なしで動作します。GitHub API を使ったオンライン検証はオプション機能であり、必須ではありません。

この設計により、ネットワーク障害時やエアギャップ環境でも一貫して動作します。

### Git 統合モデル

secretenv は `.secretenv/` ディレクトリを Git で管理します。これには重要な意味があります。

**PR レビューがセキュリティゲートになる**: 新しいメンバーが参加するとき、そのメンバーの公開鍵ファイルが PR として提出されます。既存メンバーがコードレビューと同じ感覚でその PR を確認してマージすることが、メンバー承認のプロセスになります。特別な承認システムを別途用意する必要はありません。

**変更履歴が自動的に残る**: Git の `git log` で誰がいつメンバーを追加・削除したか、どの secrets が更新されたかを追跡できます。

**`.secretenv/` を `.gitignore` に追加してはいけません**。これは意図的に Git で管理するディレクトリです。

### Policy-Less 設計

secretenv には「誰がどの secret にアクセスできるか」を定義するポリシーファイルがありません。代わりに、**誰が受信者（recipients）であるかは暗号ファイル自身が記憶**しています。

暗号ファイルの中に、各受信者に向けて暗号化されたコンテンツ鍵（wrap）が格納されています。自分の秘密鍵を持つメンバーだけが自分の wrap を復号でき、そこからコンテンツ鍵を取り出して secret を読み取れます。

### 差分に強い kv-enc

`.env` 形式の secrets を管理する `kv-enc` 形式は、**エントリ単位で暗号化**されています。

あるキーの値だけを更新した場合、そのエントリだけが変更され、他のエントリは変わりません。これにより Git diff が最小限になり、レビューがしやすくなります。また、新しいエントリを追加するときに既存エントリを復号する必要がないため、効率的です。

### 開示追跡

メンバーを削除して rewrap を実行すると、削除されたメンバーへの開示履歴（`removed_recipients`）が暗号ファイルに記録されます。

これは「削除されたメンバーはこの secret に以前アクセスできた」という事実を追跡するための仕組みです。`secretenv inspect` でこの履歴を確認し、必要に応じて secret の値を更新する判断ができます。

---

## 3. コアコンセプト（用語解説）

この章では、以降の章で頻繁に登場する用語を説明します。コマンドの使い方を読む前にここを一読しておくと理解がスムーズです。

### Workspace

Git リポジトリ内の `.secretenv/` ディレクトリが Workspace です。チームで共有する暗号ファイルとメンバー情報を格納します。

```
.secretenv/
├── members/
│   ├── active/       ← 承認済みメンバーの公開鍵
│   └── incoming/     ← 承認待ちメンバーの公開鍵
├── secrets/          ← 暗号化された secrets
└── config.toml       ← ローカル設定（オプション）
```

secretenv は、カレントディレクトリから上位ディレクトリに向かって `.secretenv/` を自動探索します。Git リポジトリのルートに到達すると探索を打ち切ります。

### Member ID

`member_id` は ASCII の識別子です。先頭は英数字（`A-Za-z0-9`）で始まり、許可文字は `A-Za-z0-9._@+-` のみ、長さは 1〜254 です（pattern: `^[A-Za-z0-9][A-Za-z0-9._@+-]{0,253}$`）。メールアドレス形式に似ていますが、`@` は必須ではありません。実際にメールを送受信する必要はなく、チーム内でユニークな識別子として機能します。

### kid（鍵世代 ID）

`01HY0G8N3P5X7QRSTV0WXYZ123` のような ULID 形式の識別子で、鍵のバージョンを表します。

1 人のメンバーが複数の kid を持てます（例: 年次ローテーション後に古い kid と新しい kid が共存）。どの kid で暗号化されたかは暗号ファイルに記録されており、適切な鍵で復号できます。

### kv-enc（KV 暗号化形式）

`.env` ファイルと同等の `KEY=VALUE` 形式を暗号化したものです。拡張子は `.kvenc`。

エントリ単位で暗号化されるため、1 つのキーを更新しても他のキーへの影響がなく、Git diff が最小限になります。日常的な secrets 管理には kv-enc の使用を推奨します。

### file-enc（ファイル暗号化形式）

任意のファイル（テキスト・バイナリ）を丸ごと暗号化する形式です。拡張子は `.encrypted`。証明書やバイナリファイルの共有に適しています。

### active / incoming

メンバーの承認状態を示します。

- **incoming**: `secretenv join` で参加申請したばかりのメンバー。まだ secrets の受信者に含まれていない
- **active**: 既存メンバーが `rewrap` で承認したメンバー。secrets の受信者に含まれる

### rewrap

メンバーの追加・削除後に、全ての暗号ファイルの受信者情報を更新する操作です。

- incoming メンバーを active に昇格させる
- active メンバーのリストと暗号ファイルの受信者を同期する
- kv-enc の場合、メンバー削除時にはコンテンツ鍵（MK）を再生成して全エントリを再暗号化する

### TOFU（初回使用時の信頼確認）

TOFU は「Trust On First Use（初回使用時に信頼する）」の略です。

`rewrap` で incoming メンバーを active に昇格させるとき、secretenv は「この公開鍵が本当に申請者のものか」を対話的に確認します。画面に GitHub のログイン名、ユーザー ID、SSH 鍵のフィンガープリントが表示され、実行者が `y` / `N` で承認を判断します。

```
Member bob@example.com
  GitHub login: bob-gh (id: 12345678)
  SSH key fingerprint: SHA256:xxxxx...
Approve? [y/N]:
```

この確認が重要な理由は、悪意のある第三者が本物のメンバーになりすまして PR を出した場合に「見覚えのない GitHub アカウントや SSH 鍵が表示される」ことで不正を検知できるからです。`--force` を指定すると TOFU 確認がスキップされるため、このセーフガードが機能しなくなります。

---

## 4. セキュリティモデル

### 鍵信頼モデル（4層）

secretenv では「この公開鍵は本当にこの人物のものか」を複数の層で確認します。単一の機構ではなく、層の組み合わせにより信頼を確立します。

| 層 | 機構 | 証明する性質 | 限界 |
|----|------|-----------|------|
| 層1 | 自己署名 | 秘密鍵保持者がこの公開鍵を作成した | 本人性は証明しない |
| 層2 | SSH attestation | secretenv 鍵と SSH 鍵の紐付け | SSH 鍵の所有者が誰かは特定できない |
| 層3 | TOFU 確認 | 鍵と人物の紐付け（目視確認） | `--force` 使用時は省略される |
| 層4 | Online verify | GitHub との照合（補助的証拠） | GitHub アカウント侵害時は無効 |

### 攻撃者モデル

| 攻撃者 | 能力 | 防御手段 |
|--------|------|---------|
| リポジトリ改ざん者 | `.secretenv/` のファイルを改ざん可能 | 署名検証により改ざんを検知 |
| 悪意ある内部者 | 正当メンバーとして復号した内容を保持 | 開示履歴で追跡（回収は不可能） |
| 公開鍵すり替え攻撃 | メンバーの公開鍵ファイルを偽造 | 自己署名・attestation・online 検証で防御 |
| 鍵ローテーション攻撃 | 古い鍵世代の wrap を流用しようとする | HPKE info に kid を含め、鍵世代不一致を検知 |

**前提**: この防御モデルは、リポジトリへの書き込みアクセスが適切に管理されていることを前提とします。GitHub の場合、`members/active/` への変更は PR レビューを通じて検証されます。

### 信頼境界

```
【信頼境界内（安全）】
  ローカル端末
  ~/.config/secretenv/keys/  ← 秘密鍵ストレージ
  SSH Ed25519 秘密鍵

【Workspace（改ざんの可能性あり）】
  .secretenv/members/        ← 署名・online 検証で防御
  .secretenv/secrets/        ← 署名検証で防御

【外部システム（オプション）】
  GitHub API                 ← online 検証時のみ使用
```

---

## 5. インストール

### 前提条件

- Rust ツールチェーン（`cargo` が使えること）
- Ed25519 形式の SSH 鍵（`~/.ssh/id_ed25519`）
- SSH エージェント（推奨）または ssh-keygen

### ビルドとインストール

```bash
# リポジトリをクローンしてインストール
git clone <secretenv-repo>
cd secretenv
cargo install --path .
```

インストール後、`secretenv --help` でコマンド一覧を確認できます。

### SSH エージェントの確認

secretenv は秘密鍵の保護に SSH 鍵を使用します。SSH エージェントが動作しているか確認してください。

```bash
# SSH エージェントの確認
ssh-add -l

# 鍵が表示されない場合は追加する
ssh-add ~/.ssh/id_ed25519
```

**注意**: SSH 鍵は必ず Ed25519 形式を使用してください（RSA 等は非対応）。

```bash
# Ed25519 鍵の生成（まだない場合）
ssh-keygen -t ed25519 -C "your@email.com"
```

### 設定（オプション）

よく使うオプションを設定ファイルに保存できます。

```bash
# デフォルトの member_id を設定（以降 --member-id を省略可能）
secretenv config set member_id alice@example.com

# GitHub アカウントを設定（online 検証を使う場合）
secretenv config set github_user alice-gh

# SSH 署名方式の設定（通常はデフォルトの auto で問題なし）
# auto: ssh-agent → ssh-keygen の順で自動選択
# ssh-agent: SSH エージェントを使用
# ssh-keygen: ssh-keygen コマンドを使用
secretenv config set ssh_signer auto

# SSH 鍵の指定（ssh-agent で複数鍵がある場合に特定の鍵を選択）
secretenv config set ssh_key ~/.ssh/id_ed25519_work
```

設定ファイルの場所は `~/.config/secretenv/config.toml` です。

---

## 6. クイックスタート（チームリーダー向け）

チームで secretenv を初めて導入するときの手順です。

### ステップ 1: リポジトリを用意する

```bash
# 既存のリポジトリで始める場合
cd /path/to/your-repo

# または新規リポジトリを作成する場合
git init my-project
cd my-project
```

### ステップ 2: Workspace を初期化する

```bash
secretenv init --member-id alice@example.com
```

実行結果:

```
Creating workspace .secretenv/
  Created members/active/
  Created members/incoming/
  Created secrets/
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
SSH signature determinism: OK
Generated and activated key for 'alice@example.com':
  Key ID:   01HY0G8N3P5X7QRSTV0WXYZ123
  Expires:  2027-03-19T00:00:00Z
Added 'alice@example.com' to members/active/
```

`init` は以下を自動で行います。

- `.secretenv/` ディレクトリ構造を作成
- ローカルに HPKE 鍵ペアを生成（`~/.config/secretenv/keys/alice@example.com/`）
- 自分の公開鍵を `members/active/alice@example.com.json` に登録

### ステップ 3: 最初の secrets を追加する

```bash
# KV 形式で secrets を追加
secretenv set DATABASE_URL "postgres://user:pass@localhost/mydb"
secretenv set API_KEY "sk-your-api-key"

# または既存の .env ファイルを一括インポート
secretenv import .env
```

### ステップ 4: Git にコミットする

```bash
git add .secretenv/
git commit -m "Initialize secretenv workspace"
```

### ステップ 5: チームメンバーに参加してもらう

Workspace の準備が完了したら、他のメンバーに [7章](#7-新メンバーとして参加する) の手順を案内します。

メンバーから PR が届いたら [10章のメンバー追加](#メンバー追加の-git-ワークフロー) に従って承認してください。

---

## 7. 新メンバーとして参加する

既存の Workspace に参加するときの手順です。

### ステップ 1: リポジトリをクローンする

```bash
git clone <repo-url>
cd my-project
```

### ステップ 2: 参加申請する

```bash
secretenv join --member-id bob@example.com
```

実行結果:

```
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
Generated and activated key for 'bob@example.com':
  Key ID:   01HWXXXXXXXXXXXXXXXXXXXXX
  Expires:  2027-03-19T00:00:00Z
Added 'bob@example.com' to members/incoming/

Ready! Create a PR to share your public key with the team.
An existing member needs to run 'secretenv rewrap' to approve your membership.
```

`join` は `init` と異なり、Workspace を作成しません。自分の公開鍵を `members/incoming/` に置くだけです。

### ステップ 3: PR を作成する

```bash
git checkout -b join/bob
git add .secretenv/members/incoming/bob@example.com.json
git commit -m "Add bob to secretenv (incoming)"
git push origin join/bob
```

GitHub（または使用している Git ホスティング）で PR を作成し、既存メンバーにレビューをリクエストします。

### ステップ 4: 既存メンバーに rewrap を依頼する

PR がマージされた後、既存メンバーが `secretenv rewrap` を実行して承認します。rewrap が完了してコミットされると、あなたが secrets を取得できるようになります。

### ステップ 5: secrets を確認する

```bash
# 最新を取得
git pull

# 動作確認
secretenv get DATABASE_URL
secretenv run -- env | grep MY_APP
```

---

## 8. 日常的な使い方（KV ストア）

### エントリの追加・更新

```bash
# 基本的な使い方
secretenv set DATABASE_URL "postgres://user:pass@localhost/db"

# 別のストア（-n オプション）に保存
secretenv set -n staging DATABASE_URL "postgres://user:pass@staging/db"
secretenv set -n prod DATABASE_URL "postgres://user:pass@prod/db"
```

ストアを指定しない場合は `default`（`.secretenv/secrets/default.kvenc`）に保存されます。

**シェル履歴に残さないために**: パスワード等は `--stdin` を使用します。

```bash
# パイプで渡す
echo "super-secret-token" | secretenv set SECRET_TOKEN --stdin

# 対話入力（パスワード等）
secretenv set SECRET_TOKEN --stdin
# → 入力待ち状態になる。入力後 Ctrl+D で確定
```

### エントリの削除

```bash
secretenv unset OLD_KEY
secretenv unset -n staging OLD_KEY
```

### エントリの取得

```bash
# 特定キーの値を取得
secretenv get DATABASE_URL

# KEY="VALUE" 形式で出力
secretenv get --with-key DATABASE_URL

# 全エントリを取得
secretenv get --all

# 全エントリを KEY="VALUE" 形式で出力
secretenv get --all --with-key

# 別のストアから取得
secretenv get -n staging DATABASE_URL
```

### キー一覧の表示

```bash
# キー名の一覧（値は表示しない）
secretenv list

# 別のストアのキー一覧
secretenv list -n staging
```

`list` は暗号を復号せずにキー名だけを表示します。値を確認するには `get` を使います。

### 環境変数として注入してコマンドを実行

```bash
# デフォルトストアの全 secrets を環境変数として注入
secretenv run -- ./my-app

# 別のストアを使う
secretenv run -n staging -- ./my-app

# 複数の引数を渡す
secretenv run -- python manage.py runserver
```

### .env ファイルの一括インポート

```bash
# .env を default ストアにインポート
secretenv import .env

# 別のストアにインポート
secretenv import -n staging staging.env
```

既存のキーは上書きされます。

---

## 9. ファイルの暗号化・復号

証明書やバイナリファイルなど、KV 形式に合わない secrets は `encrypt` / `decrypt` を使います。

### 暗号化

```bash
# ファイルを暗号化（カレントディレクトリに <filename>.encrypted を生成）
secretenv encrypt certs/ca.pem
# → ./ca.pem.encrypted

# 出力先を指定
secretenv encrypt certs/ca.pem --out .secretenv/secrets/ca.pem.encrypted
```

暗号化と同時に署名が付与されます。

### 復号

```bash
# 署名検証 → 復号の順で実行される
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

### メタデータの確認

暗号ファイルを復号せずに内容を確認できます。

```bash
secretenv inspect .secretenv/secrets/default.kvenc
secretenv inspect ca.pem.encrypted
```

表示される情報:

- 受信者（recipients）一覧
- 署名者と署名の kid
- 暗号アルゴリズム
- 作成日時・更新日時
- 開示履歴（削除されたメンバーへの開示記録）

### 使用すべき場面とすべきでない場面

| 場面 | 推奨 | 理由 |
|------|------|------|
| `.env` の key-value | kv-enc（`set`, `import`） | diff が最小、エントリ単位の操作が可能 |
| 証明書ファイル（PEM） | file-enc（`encrypt`） | バイナリ対応 |
| SSH 秘密鍵 | file-enc（`encrypt`） | バイナリ対応 |
| 数十 MB 以上のファイル | 外部ストレージを検討 | base64 エンコードでサイズが約 4/3 倍になる |
| 数百 MB 以上のファイル | 非推奨 | Git リポジトリに大容量ファイルを入れることになる |

---

## 10. メンバー管理

### メンバー追加の Git ワークフロー

新メンバーが `secretenv join` で PR を作成したら、以下のフローで承認します。

**なぜ PR レビューが重要か**: PR をレビューしてマージする行為は「この人物の公開鍵を信頼する」という意思決定です。見知らぬ人からの PR を確認もせずにマージすることは、その人を secrets の受信者として追加することを意味します。

```bash
# 1. 新メンバーの PR をマージした後、最新を取得
git pull

# 2. rewrap を実行
#    - online 検証（GitHub API での照合）を自動実行
#    - TOFU 確認（表示された鍵情報を目視確認）
secretenv rewrap

# TOFU 確認の例（3章で説明した確認プロンプト）:
# Member bob@example.com
#   GitHub login: bob-gh (id: 12345678)
#   SSH key fingerprint: SHA256:xxxxx...
# Approve? [y/N]: y    ← 本当にこの人の鍵か確認してから y を押す

# 3. 変更をコミット・プッシュ
git add .secretenv/
git commit -m "Approve bob and rewrap secrets"
git push
```

`rewrap` が完了すると:
- `members/incoming/bob@example.com.json` が `members/active/` に移動する
- 全ての暗号ファイルに bob の wrap（暗号化されたコンテンツ鍵）が追加される

### メンバー一覧の確認

```bash
# 全メンバー（active + incoming）を表示
secretenv member list

# 特定メンバーの詳細を確認
secretenv member show bob@example.com
```

### メンバー検証

```bash
# 全メンバーの公開鍵を検証（online 検証あり）
secretenv member verify

# 特定メンバーのみ検証
secretenv member verify alice@example.com bob@example.com
```

### メンバー削除

**重要な注意事項**: メンバーを削除して rewrap しても、そのメンバーが**過去に取得した secrets の値は無効になりません**。暗号学的に「過去の開示を回収」することは不可能です。

```bash
# 1. メンバーを workspace から削除
secretenv member remove alice@example.com

# 2. rewrap を実行（全暗号ファイルから alice を削除）
#    kv-enc の場合: コンテンツ鍵（MK）が再生成され、全エントリが再暗号化される
#    file-enc の場合: alice の wrap が削除される
secretenv rewrap

# 3. コミット
git add .secretenv/
git commit -m "Remove alice from secretenv"
```

### 削除後に必ず行うべきこと

1. **secrets の値を更新する**: 削除されたメンバーが知っていた値を新しい値に変更します

```bash
secretenv set API_KEY "new-api-key"
secretenv set DATABASE_PASSWORD "new-password"
```

2. **開示履歴を確認する**: `secretenv inspect` で削除されたメンバーへの開示記録を確認します

3. **開示履歴をクリアする**: secrets の値を更新したら、開示履歴をクリアできます

```bash
secretenv rewrap --clear-disclosure-history
```

---

## 11. 鍵の管理とローテーション

### 鍵の状態

| 状態 | 説明 |
|------|------|
| active | 暗号化・署名に使用される鍵。member_id につき 1 つ |
| available | 復号可能だが暗号化・署名には使用しない |
| expired | 有効期限切れ。復号は可能（警告あり） |

### 鍵の一覧

```bash
secretenv key list
```

### 定期ローテーション

鍵はデフォルトで生成から 1 年後に期限切れになります。期限切れ 30 日前から警告が表示されます。

```bash
# 1. 新しい鍵を生成（自動で active になる）
secretenv key new

# 有効期限を指定する場合
secretenv key new --expires-at 2028-01-01T00:00:00Z
secretenv key new --valid-for 2y    # 2年
secretenv key new --valid-for 180d  # 180日

# 2. workspace の自分の公開鍵を更新
secretenv init --force

# 3. PR を作成・マージ
git add .secretenv/members/active/alice@example.com.json
git commit -m "Rotate alice's key"
git push

# 4. マージ後: 全 secrets の wrap を新しい鍵で更新
secretenv rewrap

# 5. コミット
git add .secretenv/secrets/
git commit -m "Rewrap secrets for alice's new key"
git push

# 6. 旧鍵は当面保持する（過去の secrets の復号に必要な場合がある）
#    十分な移行期間後に削除
secretenv key remove <old_kid>
```

### コンテンツ鍵のローテーション

メンバー鍵のローテーションとは別に、暗号ファイルのコンテンツ鍵（MK/DEK）自体をローテーションできます。

```bash
secretenv rewrap --rotate-key
```

これにより全ファイルの MK/DEK が再生成され、過去に削除されたメンバーが以前取得したコンテンツ鍵が無効になります。

### 特定の鍵をアクティブ化

```bash
secretenv key activate <kid>
```

### 旧鍵の保持期間の目安

旧鍵を削除する前に、以下を確認してください。

- チーム全員が新しい鍵で rewrap された暗号ファイルを取得済みであること
- 旧鍵で暗号化された secrets の復号が必要な運用がなくなったこと

目安として、rewrap 完了から 1〜3 ヶ月は旧鍵を保持することを推奨します。

---

## 12. 運用ガイドライン

### 退職者が出たときのチェックリスト

1. `secretenv member remove <member_id>` でメンバーを削除
2. `secretenv rewrap` で全暗号ファイルを更新
3. `git add .secretenv/ && git commit -m "Remove <member>"` でコミット
4. `secretenv inspect` で開示履歴を確認
5. 退職者が知っていた可能性のある secrets の値を更新（API キー、パスワード等）
6. 更新後に `secretenv rewrap --clear-disclosure-history` で開示履歴をクリア
7. 関連サービス（GitHub、AWS、DB 等）でもアクセス権の削除を確認

### 秘密値の更新義務

**暗号削除は情報消去ではありません**。`member remove` + `rewrap` は「今後そのメンバーが新しい secrets を復号できなくする」ことができますが、「すでに復号した値を無効にする」ことはできません。

真にセキュリティを確保するには、退職者や離脱したメンバーが知っていた可能性のある値を必ず更新してください。

### CI/CD での利用と `--force` のリスク

CI/CD 環境では TTY（対話端末）が使えないため、`rewrap` の TOFU 確認を自動でスキップする `--force` が必要になる場合があります。

**`--force` のリスク**: 3章で説明した通り、TOFU 確認は公開鍵すり替え攻撃に対する「最後の防御層」です。`--force` でこれをスキップすると、不正な公開鍵が紛れ込んでも気付けない可能性があります。

CI/CD で `--force` を安全に使うためのルール:

1. **新メンバーの承認は対話環境で先に完了させる**: CI/CD を実行する前に、対話端末で `rewrap` を実行して incoming メンバーを active に昇格させておく。CI/CD は既に active なメンバーへのアクセスにのみ使う
2. **`--force` 後は事後確認する**: `secretenv member verify` で全メンバーの GitHub 照合を実施する
3. **`--force` の使用を限定する**: `--force` は CI/CD パイプラインなど限られた場所でのみ使用し、日常の対話操作では使わない

なお、online 検証で明示的に失敗したメンバーは `--force` 使用時でも昇格が拒否されます。

```yaml
# GitHub Actions の例
- name: Run app with secrets
  env:
    SECRETENV_MEMBER_ID: ci@example.com
    SECRETENV_HOME: /tmp/secretenv
  run: |
    secretenv run --force -- ./my-app
```

**推奨**: CI/CD 用の専用メンバー ID（例: `ci@example.com`）を作成し、ローテーション管理を明確にします。

### `secretenv inspect` による定期監査

```bash
# 各暗号ファイルのメタデータを確認
secretenv inspect .secretenv/secrets/default.kvenc

# 確認ポイント:
# - recipients に不要なメンバーが含まれていないか
# - removed_recipients（開示履歴）に注意すべきエントリがないか
# - 署名者が正しいか
# - 期限切れ間近の鍵が使われていないか
```

### `.gitignore` に追加すべきでないもの

`.secretenv/` ディレクトリ全体を `.gitignore` に追加しないでください。これは意図的に Git で管理するディレクトリです。

ただし、復号した平文ファイルは `.gitignore` に追加すべきです。

```gitignore
# 復号した一時ファイルは無視する
*.pem
.env
```

---

## 13. よくある質問（FAQ）

### Q: サーバーは必要ですか？

不要です。secretenv はサーバーレスで動作します。暗号ファイルは Git リポジトリに格納され、コマンドはローカルで実行されます。GitHub API を使ったオンライン検証はオプション機能です。

### Q: GitHub に公開鍵ファイルをコミットしても安全ですか？

安全です。`members/active/*.json` には公開鍵（暗号化用の公開鍵と SSH 公開鍵のフィンガープリント）が含まれますが、秘密鍵は一切含まれません。公開鍵は名前の通り公開しても問題ない情報です。

実際に secrets を復号するためには、ローカルの `~/.config/secretenv/keys/` にある秘密鍵が必要です。この秘密鍵は Git に含まれません。

### Q: メンバーを削除すれば過去の secrets は消えますか？

消えません。メンバーを削除して rewrap しても、そのメンバーが過去に復号した値は依然としてそのメンバーの手元に存在する可能性があります。

「削除後に secrets が漏洩するリスクをゼロにしたい」場合は、そのメンバーが知っていた可能性のある secrets の値（API キー、パスワード等）を必ず新しい値に更新してください。

### Q: SSH エージェントが必要な理由は？

secretenv の秘密鍵（HPKE 秘密鍵）は、パスフレーズの代わりに SSH Ed25519 鍵で保護されています。secretenv を操作するたびに SSH 鍵を使った復号が必要になるため、毎回パスフレーズを入力せずに済むよう SSH エージェントを使うと便利です。

SSH エージェントが使えない環境では `--ssh-keygen` オプションで `ssh-keygen` コマンドによる署名に切り替えることもできます。

SSH エージェントに複数の鍵がロードされている場合、`-i` オプションまたは `ssh_key` 設定で使用する鍵を明示的に指定できます：

```bash
secretenv encrypt -i ~/.ssh/id_ed25519_work secret.env
```

### Q: 複数のプロジェクトで別々の secrets を管理したいのですが？

各 Git リポジトリに独立した `.secretenv/` を持てます。プロジェクトごとに `secretenv init` を実行し、それぞれ独立した Workspace として管理します。

同じメンバーが複数のプロジェクトに参加する場合でも、HPKE 鍵は各 Workspace に独立した受信者として登録されます。

### Q: `secretenv run` と `.env` ファイルを手動で読み込む方法、どちらがよいですか？

`secretenv run` の使用を推奨します。理由は以下の通りです。

- 平文の `.env` ファイルがディスクに残らない
- 実行のたびに最新の secrets を復号するため、値の更新が即座に反映される
- 署名検証が自動で実行され、改ざんされた secrets でのコマンド実行を防げる

---

## 14. コマンドリファレンス（早見表）

### 共通オプション（全コマンドで使用可能）

| オプション | 説明 |
|-----------|------|
| `--home <path>` | ベースディレクトリを指定（デフォルト: `~/.config/secretenv/`） |
| `-w` / `--workspace <path>` | Workspace Root を指定 |
| `-m` / `--member-id <id>` | member_id を指定 |
| `-i` / `--identity <path>` | SSH 鍵ファイルパスを指定（ssh-agent での鍵選択にも使用） |
| `--ssh-agent` | SSH エージェントを使用 |
| `--ssh-keygen` | ssh-keygen コマンドを使用 |
| `--json` | JSON 形式で出力 |
| `-q` / `--quiet` | 最小限の出力 |
| `-v` / `--verbose` | 詳細ログを出力 |
| `-f` / `--force` | 確認プロンプトをスキップ |

### 初期化・参加

| コマンド | 説明 |
|---------|------|
| `secretenv init [--member-id <id>] [--force]` | Workspace を初期化または参加（active に直接登録） |
| `secretenv join [--member-id <id>] [--force]` | 既存 Workspace に参加申請（incoming に登録） |

### KV 操作

| コマンド | 説明 |
|---------|------|
| `secretenv set [-n <name>] <KEY> <VALUE>` | エントリを追加・更新 |
| `secretenv set [-n <name>] <KEY> --stdin` | stdin から値を読み込んでセット |
| `secretenv get [-n <name>] <KEY>` | 特定キーの値を取得・表示 |
| `secretenv get [-n <name>] --all` | 全エントリを取得・表示 |
| `secretenv get [-n <name>] [--all] --with-key` | `KEY="VALUE"` 形式で出力 |
| `secretenv unset [-n <name>] <KEY>` | エントリを削除 |
| `secretenv list [-n <name>]` | キー名の一覧を表示（値は表示しない） |
| `secretenv import [-n <name>] <file>` | `.env` ファイルを一括インポート |
| `secretenv run [-n <name>] -- <command>` | secrets を環境変数として注入してコマンドを実行 |

### ファイル操作

| コマンド | 説明 |
|---------|------|
| `secretenv encrypt <file> [--out <path>]` | ファイルを暗号化（file-enc） |
| `secretenv decrypt <file> --out <path>` | ファイルを復号 |
| `secretenv inspect <file>` | 暗号ファイルのメタデータを表示（復号不要） |

### メンバー管理

| コマンド | 説明 |
|---------|------|
| `secretenv member list` | 全メンバーを一覧表示 |
| `secretenv member show <member_id>` | 特定メンバーの詳細を表示 |
| `secretenv member verify [<member_id>...]` | メンバーの公開鍵を検証（online 検証あり） |
| `secretenv member remove <member_id>` | メンバーを Workspace から削除 |
| `secretenv rewrap [--force] [--rotate-key] [--clear-disclosure-history]` | incoming → active 昇格 + 全暗号ファイルの受信者同期 |

### 鍵管理

| コマンド | 説明 |
|---------|------|
| `secretenv key new [--expires-at <datetime>] [--valid-for <duration>]` | 新しい鍵を生成（自動で activate） |
| `secretenv key list` | 鍵一覧を表示 |
| `secretenv key activate <kid>` | 特定の鍵を active にする |
| `secretenv key remove <kid>` | 鍵を削除 |

### 設定

| コマンド | 説明 |
|---------|------|
| `secretenv config set <key> <value>` | 設定値をセット |
| `secretenv config get <key>` | 設定値を取得 |
| `secretenv config list` | 設定一覧を表示 |
| `secretenv config unset <key>` | 設定値を削除 |

設定キー: `member_id`, `ssh_signer`（`auto` / `ssh-agent` / `ssh-keygen`）, `ssh_key`, `github_user`

---

*このガイドは secretenv の日常的な使用に必要な情報を網羅しています。より詳細な暗号仕様や内部設計については、プロジェクトの内部ドキュメントを参照してください。*
