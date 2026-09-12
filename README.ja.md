# Sopshelf

[English](README.md)

> **開発中版** — Sopshelf は現在開発中です。インターフェース、既定値、配布方式は今後変更される可能性があります。新しいビルドを試す前に、暗号化済みSecret storeとage identityを必ずバックアップしてください。

Sopshelf は、既存の **SOPS + age** Secret storeを扱うための軽量なWindowsデスクトップGUIです。独自のSecretデータベースは作らず、SOPSで暗号化されたファイルを正本として使用します。

## 主な機能

- SOPS暗号化JSONに保存されたトップレベル文字列Secretの一覧表示。
- Secret値は既定でマスクし、Reveal後15秒で自動的に再マスク。
- Secret値をクリップボードへコピーし、30秒後も同じ値が残っている場合のみ自動消去。
- `sops set --value-stdin` による追加・更新。Secret値をコマンドライン引数へ載せません。
- 確認後に `sops unset` で削除。
- 変更前の暗号化済みファイルだけを履歴バックアップとして保持。
- SOPS、暗号化store、age identity、復号可否、任意の復旧バックアップをHealth表示。
- 選択したSecretだけを子PowerShellのProcess環境変数へ一時注入。
- ローカルのアプリ用パスワード検証によるGUI起動ガード。
- PySide6によるD. Vibrant UI、検索、絞り込み、コマンドパレット、キーボードショートカット。

## セキュリティ境界

SopshelfはSOPSのGUIであり、**SOPSやageの代替ではありません**。

- Secret値を意図的にログや平文一時ファイルへ書き出しません。
- Secret更新値はstdin経由でSOPSへ渡します。
- SOPSのstdout/stderr詳細をユーザー向けエラーへそのまま露出しません。
- 起動パスワードが保護するのは **Sopshelf GUIのみ** です。同じOSユーザー権限のソフトウェアは `sops.exe` を直接実行したり、ローカルファイルを変更できます。
- age秘密鍵が最重要のRoot credentialです。別途安全に保護し、復旧可能なバックアップを用意してください。

## 必要環境

- Windows 10/11
- Python 3
- PySide6
- SOPS
- age

Python側の直接依存をインストールします。

```powershell
py -3 -m pip install PySide6
```

SOPSとageは外部ツールとして使用し、Sopshelfには同梱しません。

## 設定

公開版では、環境固有のパスを環境変数で指定できます。

| 環境変数 | 用途 | 既定値 |
|---|---|---|
| `SOPSHELF_SECRET_FILE` | 暗号化JSON store | `%USERPROFILE%\.config\sops\secrets\global.sops.json` |
| `SOPS_AGE_KEY_FILE` | SOPSが使用するage identity | `%APPDATA%\sops\age\keys.txt` |
| `SOPSHELF_BACKUP_FILE` | 任意の復旧バックアップHealth確認先 | `%USERPROFILE%\.config\sops\backups\age-keys-backup.txt.age` |
| `SOPS_EXE` | `sops.exe` の明示パス | `PATH` 上の `sops`、その後に標準WinGet配置先 |

暗号化storeは、トップレベルがJSON objectで、各値が文字列である必要があります。

暗号化前の論理構造例:

```json
{
  "SERVICE_API_KEY": "example",
  "ALERT_WEBHOOK_URL": "example"
}
```

平文Secretファイルやage秘密鍵をこのリポジトリへコミットしないでください。

## 起動

次をダブルクリックします。

```text
run_sopshelf.cmd
```

またはコンソールを表示せず起動します。

```powershell
pyw -3 sopshelf.py
```

Secret値を表示しないHealth check:

```powershell
py -3 sopshelf.py --check
```

Health checkは状態とSecret件数だけを出力し、Secret値は表示しません。

## キーボードショートカット

- `Ctrl+K` — 検索へフォーカス
- `Ctrl+Shift+P` — コマンドパレット
- `F5` — 再読み込み
- `Esc` — Reveal中の値を再マスク

## 任意のModora連携

`modora.module.json` と `modora-adapter.mjs` は、互換Modora host向けにopen/status/signals連携を提供します。adapterはSopshelfの値非表示Health checkを利用し、Secret値を直接読み取りません。

## テスト

```powershell
py -3 test_sopshelf_core.py
py -3 test_sopshelf_auth.py
py -3 test_sopshelf_integration.py
$env:QT_QPA_PLATFORM = "offscreen"
py -3 test_sopshelf_ui.py
py -3 sopshelf.py --check
```

Real SOPS integration testは暗号化storeの一時コピーに対して実行し、ローカルにSOPS + age環境がない場合はskipします。

## PySide6 / Qt

GUIにはPySide6（Qt for Python）を使用しています。PySide6 Community EditionはLGPL-3.0/GPL-3.0で提供され、別途商用ライセンスもあります。配布する場合は、実際に使用するPySide6/Qtビルドのライセンス要件を確認してください。

## プロジェクト状態

このリポジトリは **開発中版** として公開します。自動テストとローカルセキュリティチェックは実施していますが、独立したセキュリティ監査済みのSecret Managerとして扱わないでください。
