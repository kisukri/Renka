#!/bin/sh
# Docker で Renka を動かすまでを全部やるスクリプト。
# 使い方（リポジトリのトップで）: sudo sh deploy/docker-setup.sh
set -eu

cd "$(dirname "$0")/.."

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mエラー: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "root で実行してください: sudo sh deploy/docker-setup.sh"
command -v docker >/dev/null 2>&1 || fail "docker が見つかりません。先に Docker をインストールしてください。"
docker compose version >/dev/null 2>&1 || fail "docker compose が使えません（Docker Compose v2 が必要です）。"

# --- ドメイン ---
if [ -f data/renka.conf ]; then
	say "data/renka.conf はもうあるので、そのまま使います（作り直すなら消してから再実行）。"
	DOMAIN=$(sed -n 's/^server_name *= *//p' data/renka.conf)
else
	say "Renka を動かすドメインを入力してください（例: matrix.example.com）"
	printf 'ドメイン: '
	read -r DOMAIN
	# https:// や末尾の / を付けてしまっても大丈夫なように
	DOMAIN=$(printf '%s' "$DOMAIN" | sed -e 's|^[a-zA-Z]*://||' -e 's|/.*$||' -e 's/[[:space:]]//g')
	case "$DOMAIN" in
		"" | *[!A-Za-z0-9.:-]*) fail "ドメインの形がおかしいです: '$DOMAIN'" ;;
	esac
	mkdir -p data
	sed -e "s|^server_name.*|server_name = $DOMAIN|" \
		-e "s|^public_base_url.*|public_base_url = https://$DOMAIN|" \
		-e "s|^listen.*|listen = 0.0.0.0:8008|" \
		-e "s|^database.*|database = /data/renka.db|" \
		-e "s|^media_dir.*|media_dir = /data/media|" \
		deploy/renka.conf.example > data/renka.conf
	say "data/renka.conf を作りました（ドメイン: $DOMAIN）"
fi

# コンテナは uid 10001 で動くので、data をそのユーザーのものにする
chown -R 10001:10001 data
chmod 750 data
chmod 640 data/renka.conf

# --- ビルドと起動 ---
port_busy() {
	if command -v ss >/dev/null 2>&1; then
		ss -ltnH 2>/dev/null | awk '{print $4}' | grep -q '[:.]8008$'
	elif command -v netstat >/dev/null 2>&1; then
		netstat -ltn 2>/dev/null | awk '{print $4}' | grep -q '[:.]8008$'
	elif command -v curl >/dev/null 2>&1; then
		curl -s -o /dev/null --max-time 2 http://127.0.0.1:8008/
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O /dev/null -T 2 http://127.0.0.1:8008/ 2>/dev/null || [ $? -eq 8 ]
	else
		return 1
	fi
}
docker compose stop >/dev/null 2>&1 || true
port_busy && fail "8008 番ポートをほかのプログラムが使っています（systemd 版の Renka が動いていませんか？ 止めるなら: sudo systemctl disable --now renka）。"
say "イメージをビルドして起動します（初回は数分かかります）"
docker compose up -d --build

say "起動を確認しています…"
up() {
	if command -v curl >/dev/null 2>&1; then
		curl -sf http://127.0.0.1:8008/_matrix/client/versions >/dev/null 2>&1
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- http://127.0.0.1:8008/_matrix/client/versions >/dev/null 2>&1
	else
		docker compose logs --since 1m renka 2>/dev/null | grep -q "listening on"
	fi
}
i=0
until up; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		docker compose logs --tail 20 renka
		fail "Renka が起動しませんでした。上のログを確認してください。"
	fi
	sleep 1
done
say "Renka は動いています（127.0.0.1:8008）"

# --- 最初のユーザー ---
say "管理者ユーザーを作ります。ユーザー名を入力してください（英小文字・数字。例: alice）"
say "（もう作ってあるなら、何も入力せずに Enter）"
printf 'ユーザー名: '
read -r NAME
if [ -n "$NAME" ]; then
	until docker compose exec renka /renka adduser -config /data/renka.conf -u "$NAME" -admin; do
		say "もう一度試します（やめるなら Ctrl-C）"
	done
fi

cat <<EOF

$(printf '\033[1m')完了しました。$(printf '\033[0m')

あとは HTTPS の設定だけです。Caddy を使うなら、次の 2 行をそのまま実行してください
（/etc/caddy/Caddyfile を上書きします。Caddy でほかのサイトも動かしているなら、上書きせずに
deploy/Caddyfile の中身を追記してください）：

  sed "s/matrix.example.com/$DOMAIN/g" deploy/Caddyfile | sudo tee /etc/caddy/Caddyfile >/dev/null
  sudo systemctl reload caddy

（Caddy がまだなら先にインストール: https://caddyserver.com/docs/install ）
そのあと Element などのアプリで、サーバーに https://$DOMAIN を指定してログインできます。
EOF
