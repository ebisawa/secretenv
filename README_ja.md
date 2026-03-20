# secretenv

`.env` を Slack や DM で送るのをやめたい。  
でも、専用サーバーや常時接続の秘密情報管理サービスを前提にしたくない。

`secretenv` は、そうしたチームのための offline-first な暗号ファイル共有 CLI です。  
`.env`、証明書、鍵ファイルなどを暗号化したまま Git リポジトリで扱い、メンバー追加や削除、鍵更新も Git のレビュー運用に載せられます。

向いているケース:

- チームで `.env` を安全に共有したい
- 証明書や設定ファイルも同じ仕組みで管理したい
- ローカル開発でも CI でも同じ secret 運用をしたい
- SaaS や専用基盤に依存せずに運用したい

このプロジェクトの狙いは、「秘密を平文で配らない」だけではありません。  
誰に共有されているか、改ざんされていないか、鍵更新やメンバー変更をどう反映するかまで、Git と相性のよい形で整理することを目指しています。

## Install

### Homebrew (macOS / Linux)

```bash
brew tap ebisawa/secretenv/secretenv
brew install secretenv
```

### Build from source

```bash
git clone <secretenv-repo>
cd secretenv
cargo install --path .
```

## Read More

まず全体像を知りたい場合:

- [Product Brief (English)](guides/product_brief_v3_en.md)
- [Product Brief (Japanese)](guides/product_brief_v3_ja.md)

実際の導入や運用手順を知りたい場合:

- [User Guide (English)](guides/user_guide_en.md)
- [User Guide (Japanese)](guides/user_guide_ja.md)

暗号設計やセキュリティモデルを詳しく確認したい場合:

- [Security Design (English)](guides/security_design_v3_en.md)
- [Security Design (Japanese)](guides/security_design_v3_ja.md)

## Status

現在はアルファ段階です。仕様策定と実装を並行して進めています。

## License

Apache-2.0. See [LICENSE](LICENSE).
