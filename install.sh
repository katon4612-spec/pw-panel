#!/usr/bin/env bash
# PassWall 节点面板 一键安装 / 更新
# 用法： bash <(curl -fsSL https://raw.githubusercontent.com/katon4612-spec/pw-panel/main/install.sh) [端口]
set -e
REPO="katon4612-spec/pw-panel"
PORT="${1:-8899}"
DIR=/opt/pw-panel
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
command -v python3 >/dev/null || {
  echo "安装 python3 ..."
  (command -v apt-get >/dev/null && apt-get update -y && apt-get install -y python3) || \
  (command -v dnf >/dev/null && dnf install -y python3) || (command -v yum >/dev/null && yum install -y python3)
}
mkdir -p "$DIR"
echo "下载面板程序 ..."
# 按最新提交编号下载，避开 raw.githubusercontent.com 约 5 分钟的缓存
SHA=$(curl -fsSL --max-time 10 "https://api.github.com/repos/$REPO/commits/main" 2>/dev/null | grep -m1 '"sha"' | cut -d'"' -f4)
REF="${SHA:-main}"
curl -fsSL "https://raw.githubusercontent.com/$REPO/$REF/pw_panel.py?t=$(date +%s)" -o "$DIR/pw_panel.py.new"
echo "版本：${REF:0:7}"
python3 -m py_compile "$DIR/pw_panel.py.new" && mv "$DIR/pw_panel.py.new" "$DIR/pw_panel.py"

cat > /etc/systemd/system/pw-panel.service <<SVC
[Unit]
Description=PassWall Panel
After=network.target

[Service]
WorkingDirectory=$DIR
ExecStart=$(command -v python3) $DIR/pw_panel.py $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
systemctl enable pw-panel >/dev/null 2>&1
systemctl restart pw-panel

# 放行端口（防火墙开着才会生效）
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow "$PORT"/tcp >/dev/null; fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --add-port="$PORT"/tcp --permanent >/dev/null && firewall-cmd --reload >/dev/null; fi

sleep 2
IP=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
PW=$(python3 -c "import json;print(json.load(open('$DIR/pw_panel_config.json'))['panel_password'])" 2>/dev/null || echo "见 $DIR/pw_panel_config.json")
USER_=$(python3 -c "import json;print(json.load(open('$DIR/pw_panel_config.json'))['panel_user'])" 2>/dev/null || echo admin)
echo
echo "=========================================="
if systemctl is-active --quiet pw-panel; then echo " ✅ PassWall 面板已运行"; else echo " ❌ 启动失败，查看：journalctl -u pw-panel -n 30"; fi
echo " 版本： ${REF:0:7}"
echo " 地址： http://$IP:$PORT"
echo " 账号： $USER_"
echo " 密码： $PW"
echo " 云服务器记得在安全组放行 TCP $PORT"
echo "------------------------------------------"
echo " 重启：systemctl restart pw-panel"
echo " 日志：journalctl -u pw-panel -n 50"
echo " 更新：重新运行这条安装命令即可（配置和密码不会丢）"
echo "=========================================="
