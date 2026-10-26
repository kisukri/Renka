#!/bin/sh
# Linux に直接（systemd で）Renka を入れるスクリプト。
# 使い方（リポジトリのトップで）: sudo sh deploy/install.sh
# もう一度実行すると、設定とデータはそのままでバイナリだけ入れ替えます（アップデート）。
set -eu

cd "$(dirname "$0")/.."

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mエラー: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "root で実行してください: sudo sh deploy/install.sh"
command -v systemctl >/dev/null 2>&1 || fail "systemd が見つかりません。Docker 版（sudo sh deploy/docker-setup.sh）を使ってください。"

# --- バイナリ ---
# sudo だと PATH から /usr/local/go/bin が消えることがあるので、そこも探す
GO=$(command -v go 2>/dev/null || true)
[ -n "$GO" ] || { [ -x /usr/local/go/bin/go ] && GO=/usr/local/go/bin/go; } || true
if [ -n "$GO" ]; then
	say "ビルドしています（$("$GO" version)）"
	CGO_ENABLED=0 "$GO" build -trimpath -ldflags="-s -w" -o renka ./cmd/renka ||
		fail "ビルドに失敗しました。Go 1.27 以上が必要です（https://go.dev/dl/）。"
elif [ -x ./renka ]; then
	say "Go がないので、ここにある ./renka を使います"
else
	fail "Go 1.27 以上が必要です（https://go.dev/dl/）。Go を入れたくなければ Docker 版（sudo sh deploy/docker-setup.sh）を使ってください。"
fi
install -m 755 renka /usr/local/bin/renka

# --- ユーザーとディレクトリ ---
if ! id renka >/dev/null 2>&1; then
	NOLOGIN=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)
	useradd -r -s "$NOLOGIN" renka
fi
mkdir -p /etc/renka /var/lib/renka
chown renka:renka /var/lib/renka
chmod 750 /var/lib/renka

# --- 設定 ---
if [ -f /etc/renka/renka.conf ]; then
	say "/etc/renka/renka.conf はもうあるので、そのまま使います。"
	DOMAIN=$(sed -n 's/^server_name *= *//p' /etc/renka/renka.conf)
	NEW=no
else
	say "Renka を動かすドメインを入力してください（例: matrix.example.com）"
	printf 'ドメイン: '
	read -r DOMAIN
	DOMAIN=$(printf '%s' "$DOMAIN" | sed -e 's|^[a-zA-Z]*://||' -e 's|/.*$||' -e 's/[[:space:]]//g')
	case "$DOMAIN" in
		"" | *[!A-Za-z0-9.:-]*) fail "ドメインの形がおかしいです: '$DOMAIN'" ;;
	esac
	sed -e "s|^server_name.*|server_name = $DOMAIN|" \
		-e "s|^public_base_url.*|public_base_url = https://$DOMAIN|" \
		deploy/renka.conf.example > /etc/renka/renka.conf
	chown root:renka /etc/renka/renka.conf
	chmod 640 /etc/renka/renka.conf
	say "/etc/renka/renka.conf を作りました（ドメイン: $DOMAIN）"
	NEW=yes
fi

# --- 起動 ---
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
systemctl stop renka 2>/dev/null || true
sleep 1
port_busy && fail "8008 番ポートをほかのプログラムが使っています（Docker 版の Renka が動いていませんか？）。止めてから再実行してください。"
cp deploy/renka.service /etc/systemd/system/renka.service
systemctl daemon-reload
systemctl enable renka >/dev/null 2>&1
systemctl restart renka

say "起動を確認しています…"
up() {
	if command -v curl >/dev/null 2>&1; then
		curl -sf http://127.0.0.1:8008/_matrix/client/versions >/dev/null 2>&1
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- http://127.0.0.1:8008/_matrix/client/versions >/dev/null 2>&1
	else
		systemctl is-active --quiet renka
	fi
}
i=0
until up; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		journalctl -u renka -n 20 --no-pager || true
		fail "Renka が起動しませんでした。上のログを確認してください。"
	fi
	sleep 1
done
say "Renka は動いています（127.0.0.1:8008）"

# --- 最初のユーザー ---
if [ "$NEW" = yes ]; then
	say "管理者ユーザーを作ります。ユーザー名を入力してください（英小文字・数字。例: alice）"
	say "（いらなければ、何も入力せずに Enter）"
	printf 'ユーザー名: '
	read -r NAME
	if [ -n "$NAME" ]; then
		until runuser -u renka -- /usr/local/bin/renka adduser -config /etc/renka/renka.conf -u "$NAME" -admin; do
			say "もう一度試します（やめるなら Ctrl-C）"
		done
	fi
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
