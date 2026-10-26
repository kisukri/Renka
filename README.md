# Renka

> Go で書いた軽量な [Matrix](https://matrix.org) ホームサーバーです。
> 実行ファイル 1 つと SQLite ファイル 1 つだけ。待機中のメモリは 10〜25MB ほどで、小さな x86 / ARM の Linux マシンでも動きます。

**日本語** · [English](README.en.md)

---

連歌（れんが）では、誰かが詠んだ句に次の人が句を付け、それがまた次の人へと渡っていきます。
一人では書けない作品が、みんなの言葉のつながりから生まれます。Renka は、その連歌にちなんで名付けました。

Renka は Go で書いた Matrix ホームサーバーで、コードは 1 万 3 千行ほどです。実行ファイル 1 つと SQLite の
データベースファイル 1 つで動き、待機中のメモリは 10〜25MB 程度。スペックの低い Linux サーバー（x86 / ARM）でも
無理なく動かせます。

Element（新しい Element X も、旧版の Element Classic も）・FluffyChat・Cinny など、普通の Matrix
クライアントがそのまま使えます。アプリを閉じていてもプッシュ通知が届きます。Synapse などほかのサーバーとの
フェデレーションにも対応していて、既定ではオフになっています（後述）。

## Matrix のしくみ（ざっくり）

**1. 何もかも「部屋のイベント」**
個別チャットもグループも、Matrix ではどれも「部屋」です。部屋で起きることはすべて JSON のイベントとして
記録されます。メッセージなら `m.room.message`、部屋名の変更なら `m.room.name`、誰かが入ってきたら
`m.room.member`。どのイベントにも固有の `event_id`、送信者、時刻、内容があります。

**2. イベントは 2 種類**
- **メッセージイベント**：チャットやリアクションなど。タイムラインに積み重なっていくだけです。
- **ステートイベント**：`state_key` を持ち、部屋の「今の状態」を表します（部屋名、メンバー、誰がどの権限を
  持っているか）。同じ `(type, state_key)` なら新しいものが古いものを上書きします。各ステートの最新値を
  集めたものが、その部屋の現在の状態です。

**3. 権限はパワーレベルで決まる**
`m.room.power_levels` というステートイベントに、各メンバーのレベル（オーナーは 100、一般は 0）と、操作ごとに
必要なレベル（部屋名の変更は 50、キックは 50、権限の変更は 100 など）が書かれています。サーバーはイベントを
受け取るたびに、送信者が部屋にいるか、レベルが足りているかを確かめます。自分より高い権限を人に与えることは
できません。

**4. クライアントは /sync で待ち受ける**
クライアントは `GET /sync?since=<前回のトークン>&timeout=30000` を呼び続けます。新しいことがあればすぐに
返事が来て、何もなければ最大 30 秒待ちます。返事には新着メッセージ、メンバーの出入り、既読、入力中、鍵の変化
などと、次に使うトークン `next_batch` が入っています。Renka はあらゆる変化に**全体で 1 本の通し番号**を振って
いるので、トークン `s123` は「123 番まで受け取った」という意味になります。

**5. 端末間暗号化：サーバーはただの配達係**
暗号化はクライアント側（Olm / Megolm）で行います。サーバーがするのは、各端末の公開鍵を預かること
（`/keys/upload`、`/keys/query`）、ワンタイム鍵を渡すこと（`/keys/claim`）、端末どうしの暗号化された
「to-device」メッセージを中継すること（`/sendToDevice`）、そしてクライアントが暗号化した鍵のバックアップを
保管することだけ。サーバーが平文を見ることはありません。

**6. フェデレーション（既定ではオフ）**
Matrix が本当の意味で分散型なのは、フェデレーションがあるからです。各サーバーは自分のイベントに署名し、
部屋の状態を複数のサーバーで一緒に持ちます。イベントは `prev_events` で有向非巡回グラフとしてつながり、
グラフが分岐したら「状態解決 v2」でまとめ直します。Matrix でいちばん複雑な部分で、Synapse や tuwunel の
コードが大きくなる一番の理由でもあります。Renka はこれをひととおり実装していて、Synapse を含むほかの
サーバーと部屋を共有できます。状態解決の結果は Synapse 本体の実装と突き合わせて確認済みで、ほかのサーバーの
ユーザーとの端末間暗号化も使えます。

## コードの構成

```
cmd/renka/        起動するだけの main
internal/server/  サーバー本体（下の表）とそのテスト
deploy/           設定の例、Docker・systemd・Caddy・Nginx 用のファイル、インストール用スクリプト
test/             API テスト（Python）、テスト用サーバーの設定、Synapse を使ったテストデータの作成
```

Go では 1 つのディレクトリが 1 つのパッケージなので、サーバー本体は `internal/server/` にまとめてあります。

| `internal/server/` | 中身 |
|---|---|
| `main.go` | 設定ファイル、コマンドライン（起動・ユーザー作成・パスワード変更） |
| `server.go` | DB スキーマ、書き込みトランザクション、通し番号、ルーティング、ステータスページ |
| `auth.go` | 登録、ログイン、端末、パスワードのハッシュ（PBKDF2）、ログイン失敗の回数制限 |
| `events.go` | イベントの保存、Renka 独自の送信ルール、取り消し |
| `pdu.go` | 部屋の認可ルール（ルームバージョン 10 / 11）、署名付きイベント、イベントグラフ |
| `rooms.go` | 部屋の作成・参加・招待・キック・BAN、送信、ステート、履歴、スレッド、エイリアス、部屋一覧 |
| `sync.go` | `/sync` のロングポーリング、フィルター、端末リストの変化 |
| `slidingsync.go` | Sliding Sync（Element X が使う新しい同期）：部屋の一覧、差分だけの送信、拡張機能 |
| `account.go` | プロフィール、アカウントデータ、プッシュルール、入力中、既読 |
| `e2ee.go` | 端末鍵、ワンタイム鍵、クロス署名、to-device メッセージ、鍵のバックアップ |
| `media.go` | ファイルのアップロード・ダウンロード、サムネイル |
| `push.go` | プッシャー、プッシュルールの判定、プッシュゲートウェイへの送信 |
| `admin.go` | 管理コマンド、`renka admin` 用のソケット、管理ルームのボット |
| `federation.go` | 正規化 JSON、署名、サーバー鍵、サーバーの探索、署名付きリクエスト |
| `fedkeys.go` | ほかのサーバーの鍵（現役のものと引退したもの）、公証サーバーへの問い合わせ |
| `stateres.go` | 状態解決 v2 |
| `fedstate.go` | 各イベント直後の部屋の状態（state group）と現在の状態 |
| `fedin.go` | イベントの受信：検証、足りないイベントや状態の取得、保存 |
| `fedserver.go` | フェデレーション API：トランザクション、イベント、状態、参加、退出、招待 |
| `fedout.go` | ほかのサーバーへの送信、サーバーをまたいだ参加と招待 |
| `fede2ee.go` | サーバーをまたいだ端末間暗号化：端末リスト、鍵、to-device メッセージ |
| `fedmedia.go` | サーバーをまたいだファイル：配信、取得、キャッシュ |

## インストール

やり方は 2 通りあります。どちらも、下のコマンドを**そのままコピーして貼り付ける**だけです。途中でドメイン、
管理者のユーザー名とパスワードを聞かれるので、それに答えてください。それ以外に書き換えるところは
ありません。

始める前に、ドメインの DNS（A レコード）をこのサーバーの IP アドレスに向けておいてください。

### A. Docker で動かす（おすすめ）

必要なもの：Docker と Docker Compose v2（`docker compose` が使えること）。

```bash
git clone https://github.com/kisukri/Renka.git
cd Renka
sudo sh deploy/docker-setup.sh
```

スクリプトがやること：`data/renka.conf` の作成（ドメインのほか、コンテナ用のパス `/data/...` と待ち受け
`0.0.0.0:8008` も設定）、`data` の持ち主をコンテナのユーザー（uid 10001）に変更、イメージのビルドと起動、
起動の確認、管理者ユーザーの作成。最後に HTTPS の設定コマンドを表示します。

- **アップデート**：`cd Renka && git pull && sudo sh deploy/docker-setup.sh`（設定とデータはそのまま）
- **ログを見る**：`docker compose logs -f renka`
- **バックアップ**：`docker compose stop` してから `data` ディレクトリをコピーします。

イメージは空の `scratch` から作っていて、中身はバイナリと CA 証明書だけです（約 19MB。libc もシェルも
なし）。コンテナは root 以外（uid 10001）で動き、ルートファイルシステムは読み取り専用、capability も
すべて外しています（`docker-compose.yml` を参照）。

### B. Linux に直接入れる（systemd）

必要なもの：systemd と Go 1.27 以降（[go.dev/dl](https://go.dev/dl/)）。

```bash
git clone https://github.com/kisukri/Renka.git
cd Renka
sudo sh deploy/install.sh
```

スクリプトがやること：ビルド、`/usr/local/bin/renka` への配置、専用ユーザー `renka` と
`/etc/renka`・`/var/lib/renka` の作成、`/etc/renka/renka.conf` の作成、systemd への登録と起動、
起動の確認、管理者ユーザーの作成。最後に HTTPS の設定コマンドを表示します。

- **アップデート**：`cd Renka && git pull && sudo sh deploy/install.sh`（設定とデータはそのまま）
- **ログを見る**：`journalctl -u renka -f`
- **バックアップ**：`sudo systemctl stop renka` してから `/var/lib/renka` をコピーします。

### パスワードを忘れたら

```bash
# Docker の場合（Renka ディレクトリで）
docker compose exec renka /renka passwd -config /data/renka.conf -u ユーザー名
# systemd の場合
sudo runuser -u renka -- renka passwd -config /etc/renka/renka.conf -u ユーザー名
```

パスワードは 2 回聞かれます（入力しても画面には表示されません）。そのユーザーのログインはすべて
切れます。

### うまくいかないとき

| 症状・ログ | 原因と直し方 |
|---|---|
| `public_base_url ... must start with https://` | 設定の `public_base_url` は `https://` から書きます（`server_name` はドメインだけ） |
| `mkdir /var: read-only file system` | Docker なのに `database` / `media_dir` が `/data/...` になっていません |
| `permission denied` | Docker なら `sudo chown -R 10001:10001 data`、systemd なら `sudo chown -R renka:renka /var/lib/renka` |
| 8008 番ポートが使われている | Docker 版と systemd 版を両方動かしていないか確認してください |

自分で設定ファイルを作ったせいで混乱したら、`data/renka.conf`（systemd なら `/etc/renka/renka.conf`）を
消してスクリプトをもう一度実行すれば、作り直してくれます。

## 設定

設定ファイルは `key = value` の形で、`#` で始まる行はコメントです（行の途中には書けません）。場所は
Docker なら `data/renka.conf`、systemd なら `/etc/renka/renka.conf`。変えたら Renka を再起動してください
（`docker compose restart` か `sudo systemctl restart renka`）。

| 項目 | 既定値 | 説明 |
|---|---|---|
| `server_name` | （必須） | ドメインだけを書きます（`https://` は付けない）。ユーザー ID が `@名前:ドメイン` になるので、**あとから変えないでください** |
| `public_base_url` | `https://` + `server_name` | アプリがつなぎに来る URL。`https://` から書きます |
| `listen` | `127.0.0.1:8008` | 待ち受けるアドレス。Docker では `0.0.0.0:8008`（外には `docker-compose.yml` で 127.0.0.1 だけに出しています） |
| `database` | `data/renka.db` | データベースのファイル。Docker では `/data/renka.db` |
| `media_dir` | `data/media` | アップロードされたファイルの置き場所。Docker では `/data/media` |
| `registration` | `false` | アプリからの新規登録を許すか。オフにして `renka adduser` で作るのがおすすめです |
| `registration_token` | なし | 登録をオンにするときの招待コード（8 文字以上）。知っている人だけが登録できます |
| `max_upload_mb` | `50` | 1 ファイルの上限。リバースプロキシの上限（Caddy の `max_size`、Nginx の `client_max_body_size`）もこれ以上にしてください |
| `media_quota_mb` | `1024` | 1 ユーザーがアップロードできる合計。管理者は対象外。`0` で無制限 |
| `remote_media_cache_mb` | `1024` | ほかのサーバーのファイル（画像・音声・動画）を手元に置いておく量。超えたら古いものから消します。`0` で無制限 |
| `push` | `true` | スマホへのプッシュ通知（下の「プッシュ通知」）。`false` で外への通信をしなくなります |
| `federation` | `false` | ほかのサーバーと部屋を共有するか（下の「フェデレーション」） |
| `trusted_key_servers` | `matrix.org` | ほかのサーバーの署名鍵を、そのサーバーが答えないときに問い合わせる先。カンマ区切り。空にすると、サーバー自身の鍵しか信じません |
| `federation_address` | `public_base_url` のホスト:443 | ほかのサーバーにつないでもらう先 |
| `search_all_users` | `false` | ユーザー検索で全員を出すか。オフだと、同じ部屋か公開部屋にいる人だけが見つかります（完全な ID を入れれば誰とでも話せます） |
| `memory_limit_mb` | `0` | メモリの目安。小さいマシンで設定すると Go がこまめにメモリを返します。`0` で制限なし |
| `trust_proxy` | `false` | リバースプロキシの後ろで動かすなら `true`。ログイン失敗の回数制限を、本当の接続元 IP で数えます |

## リバースプロキシと HTTPS

Renka は `127.0.0.1:8008` で平文の HTTP を話します。TLS は前に置いた Caddy か Nginx に任せ、`/_matrix/*`
と `/.well-known/matrix/*`（それとステータスページの `/`）を転送してください。

**Caddy**（`deploy/Caddyfile`）：証明書の取得も更新も自動です。インストール用スクリプトが最後に、ドメインを
入れた設定を `/etc/caddy/Caddyfile` に書き込むコマンドを表示します。Caddy 自体のインストールは
[こちら](https://caddyserver.com/docs/install)。

**Nginx**（`deploy/renka.nginx.conf.example`）：`matrix.example.com` を自分のドメインに置き換えて
`/etc/nginx/sites-available/` に置き、`sites-enabled/` にリンクします。証明書は先に
`sudo certbot --nginx -d あなたのドメイン` で取り、`sudo nginx -t && sudo systemctl reload nginx` で反映します。
中身のポイント：アップロード用の `client_max_body_size`、`trust_proxy` で使う `X-Forwarded-For`、`/sync` の
ロングポーリングに合わせた長めの `proxy_read_timeout`、そして `/` のステータスページ。nginx 1.25.1 より古いなら
`http2 on;` を消して `listen 443 ssl http2;` にしてください。

**ドメインを分けるとき**：`server_name` を `example.com`、サーバーを `matrix.example.com` で動かすなら、
`example.com` 側で `/.well-known/matrix/client` に `{"m.homeserver":{"base_url":"https://matrix.example.com"}}`
を返してください（フェデレーションするなら `/.well-known/matrix/server` に
`{"m.server":"matrix.example.com:443"}` も）。Caddy なら次のとおりです：

```
example.com {
	header /.well-known/matrix/* Access-Control-Allow-Origin *
	respond /.well-known/matrix/client `{"m.homeserver":{"base_url":"https://matrix.example.com"}}`
	respond /.well-known/matrix/server `{"m.server":"matrix.example.com:443"}`
}
```

Renka には **Web のチャット画面はありません**。ブラウザでドメインを開いても、サーバーが動いていることを
知らせる短いテキストが出るだけです。チャットするときは、Element などの Matrix クライアントで
`https://あなたのドメイン` を指定してください。

## プッシュ通知

アプリを閉じていても、スマホに通知が届きます。通知設定に引っかかるメッセージが来ると、Renka はそのユーザーの
プッシュゲートウェイ（Element なら matrix.org のもの）に知らせ、ゲートウェイが Apple や Google を通して
アプリを起こします。

サーバーの外に出るのはイベント ID、ルーム ID、未読数だけ。ゲートウェイにも Apple や Google にも、
メッセージの中身や送り主は見えません。アプリは起きたあと、自分でサーバーにメッセージを取りに来ます。
ゲートウェイの宛先はアプリが決めるものなので、内部やプライベートなアドレスへの接続は Renka が断ります。
`push = false` にすれば丸ごとオフにできます。

## 管理コマンド

サーバー管理者（`renka adduser -admin` か `users make-admin` で設定）は、2 つのやり方で管理できます。

- **サーバー上から**：`renka admin -config /etc/renka/renka.conf users list` のように実行します（renka
  ユーザーか root で）。Docker なら `docker compose exec renka /renka admin -config /data/renka.conf users list`。
  そのユーザーしか開けないソケットを通して、動いているサーバーとやりとりします。
- **管理ルームから**：管理者はみんな、ボットの @renka から「Renka admin」という部屋に招待されます。
  そこで `users list` や `!admin rooms list` のように打ち込めば OK です。言うことを聞くのはその時点の
  管理者だけで、パスワードを含む返信は 10 分たつと消えます。

`help` で一覧が出ます。アカウント（一覧、詳細、作成、パスワードの再設定、ログアウト、無効化、管理者の
付与と解除）、部屋（一覧、詳細、閉鎖）、メディア（使用量、削除）、サーバーの統計が使えます。

## フェデレーション（実験的・既定ではオフ）

`federation = true` にすると、ほかの Matrix サーバーのユーザーとも部屋を共有できるようになります。

- **よそのサーバーの部屋に入る**：ID かエイリアス（`#room:matrix.org` など）で参加できます。ほかのサーバー
  からの招待も受けられます。
- **よそのサーバーの人を招く**：招いた人は参加も退出もでき、キックや BAN も普通にできます。
- **メッセージ、ステートの変更、入力中、既読**はどちらの向きにも届きます。参加した部屋で上にスクロール
  すれば、参加する前の履歴もほかのサーバーから取ってきます。
- **端末間暗号化**：端末の鍵、ワンタイム鍵、クロス署名の鍵、to-device メッセージ（部屋の鍵はこれで
  受け渡されます）がサーバーをまたいで届き、相手の端末が変わればクライアントに知らせます。端末の名前は
  ほかのサーバーに渡しません。
- **分岐は状態解決 v2 でまとめる**：いくつかのサーバーが同時に変更しても、Synapse と Renka は同じ状態に
  落ち着きます（本物の Synapse で確かめてあります）。
- **抜けたイベントは取りに行く**：障害のあとでもちゃんと追いつきます。届かないサーバーには間隔をあけながら
  （最大 6 時間）送り直し、再起動しても取りこぼしません。
- **イベントはすべて検証する**：署名（鍵はそのサーバーから取得し、返事がなければ `trusted_key_servers` の
  公証サーバーに聞きます。既定は Synapse と同じく `matrix.org`）、内容のハッシュ（改ざんされたものは
  取り消した形でしか残しません）、部屋の認可ルール。今の状態で見たときだけルールに合わないイベントは
  「ソフトフェイル」として、グラフには残しつつ画面には出しません。
- **画像・音声・動画**：ほかのサーバーのファイルは、最初に開いたときに取ってきて手元に置きます
  （`remote_media_cache_mb` まで）。こちらのファイルも、ほかのサーバーに渡せます（Matrix 1.11 の認証付き
  メディア。古いサーバーには従来の方法で）。
- **プライバシー**：サーバーが見られるのは、自分のユーザーがいる部屋だけです。履歴をメンバー限定にしている
  部屋では、参加より前のメッセージは取り消した形で渡します。サーバー ACL（`m.room.server_acl`）にも
  従います。
- **上限**：ステートが 2 万イベント（または 32MB）を超えるような大きな部屋には参加できません。

`"m.federate": false` で作った部屋と、フェデレーションをオンにする前からある部屋は、ローカルのままです。
フェデレーションする部屋では、イベントの中に入れられる数値は整数だけです（署名付きイベントの決まりで、
Synapse も同じです）。

**まだできないこと**：オンライン状態（presence）、部屋のアップグレード、ほかのサーバーの公開部屋一覧。

ほかのサーバーは `https://あなたのドメイン/.well-known/matrix/server`（Renka が返します）を見て 443 番ポートに
つなぎに来るので、ポートを追加で開ける必要はありません。`/_matrix/*` と `/.well-known/matrix/*` はもう
リバースプロキシで転送しているはずです。別の場所につながせたいときは `federation_address` を設定してください。

使わないならオフのままにしておきましょう。フェデレーションをオンにするということは、自分の管理下にない
サーバーからのリクエストを受け入れるということです。

## 自分でビルドする

Go 1.27 以降が必要です。どの OS からでも Linux 向けにクロスコンパイルできます。

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o renka-linux-arm64 ./cmd/renka
```

## テスト

```bash
go test -race ./...                   # ユニットテスト（ファズのシードも流れます）
go test -run='^$' -fuzz=FuzzEndpoints ./internal/server # 40 ほどのエンドポイントにでたらめな入力を投げるファズ（Ctrl-C で止まります）

./renka -config test/test.conf     # テスト用サーバーを起動
python test/api_test.py               # 別のターミナルで：API のテスト約 70 項目
python test/edge_test.py              # 境界値・悪用・回帰のチェック約 100 項目
```

`internal/server/testdata/synapse_vectors.json.gz` は Synapse 自身のコードで作ったテストケースです（`test/synapse_vectors.py`）。
`go test` で、Renka の認可ルール、取り消し、ハッシュ、署名、イベント ID が Synapse と同じ結果になるかを
確かめます。`test/check_pdus.py` では、Renka が署名したイベントを Synapse に検証させます。
`internal/server/testdata/stateres_vectors.json.gz`（`test/stateres_vectors.py`）は、分岐した部屋を Synapse が状態解決した
結果です。`TestSynapseInterop` は本物の Synapse と双方向に部屋を共有するテストで、動かし方は
`test/synapse_interop.md` に書いてあります。

`edge_test.py` は最後にその IP のログイン回数制限を発動させるので、続けてもう一度流すときはテスト用サーバーを
再起動してください。

## リリース

`v` で始まるタグを push すると、GitHub Actions が x86 と ARM のバイナリをビルドして Releases に載せます。

```bash
git tag v1.1.0 && git push origin v1.1.0
```

## できること

登録（招待トークンも設定可）、ログイン、複数端末、パスワード変更 · 部屋の作成（個別・グループ・公開）、招待、
参加、退出、キック、BAN · 送信、編集、リアクション、取り消し · スレッド · 履歴のさかのぼり、特定のイベントへの
ジャンプ · **Sliding Sync**（Element X 用。部屋の一覧、購読、to-device・暗号化・既読・入力中・アカウント
データの拡張）· 古い API パス（`r0`）· 既読、未読数、入力中 · 部屋のエイリアス、公開部屋の一覧、ユーザー検索 · アイコンと表示名 ·
端末間暗号化（鍵のアップロード・取得・受け取り、クロス署名、to-device メッセージ、鍵のバックアップ）·
ファイルや画像のアップロード、サムネイル · プッシュルールと**プッシュ通知** · **管理コマンド**（CLI と
管理ルーム）· ユーザーごとのメディア容量の上限 · 制限付きの部屋（ほかの部屋のメンバーなら参加できる）·
**フェデレーション**：ほかのサーバーとの部屋の共有（参加、招待、メッセージ、ステート、履歴、入力中、既読、
状態解決、端末間暗号化、画像・音声・動画のやりとり）、プロフィールとエイリアスの問い合わせ

## まだできないこと

- オンライン状態（presence）、ほかのサーバーの公開部屋一覧を見ること
- メッセージ検索（`/search`）、Spaces の階層 API、ノックでの参加（knock）、部屋のアップグレード
- Web 管理画面向けの HTTP 管理 API（Synapse 互換）
- 音声・ビデオ通話用の TURN サーバーの設定
- 履歴の公開範囲は「メンバーなら全部見られる／抜けたあとの新着は見えない」の 2 段階だけで、`joined` と
  `invited` は区別していません

---

## ライセンス

[MIT](LICENSE) — Copyright (c) 2026 Renka contributors.

自由に使ったり、手を加えたり、配ったりしてかまいません。「現状のまま」の提供で、保証は一切ありません。
全文は [LICENSE](LICENSE) をご覧ください。
