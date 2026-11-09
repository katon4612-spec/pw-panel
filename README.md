# PassWall 节点面板

通过 frp 远程管理多台软路由，在一个网页里查看所有盒子的 PassWall 节点状态。路由器上不用装任何东西。

- 所有盒子一览：frp 在线/离线、当前节点、外网（谷歌）延迟、国内（百度）延迟
- 自动判断问题：节点坏了 / 盒子本身没网 / 盒子掉线
- 节点测速、一键切换、粘贴分享链接添加新节点
- 一键修复：自动挑能用的最快备用节点切过去
- 从 frps 一键导入盒子
- 掉线通知：企业微信 / 钉钉机器人 / Telegram
- 批量操作：勾选多台一起加节点、切模式、开关 PassWall、自动切换、重启
- 到期提醒：手动填或从节点名自动识别，提前 7 天提醒
- 自动切换节点、历史记录、重启盒子、手机版排版

## 一键安装 / 更新

用 root 登录服务器，执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/katon4612-spec/pw-panel/main/install.sh)
```

想换端口（默认 8899）就在后面加端口号：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/katon4612-spec/pw-panel/main/install.sh) 9988
```

装完会显示面板地址、账号和密码。云服务器记得在安全组里放行这个端口。

## 首次使用

1. 打开面板，点「设置」：填 frps 面板的地址和账号密码，再填软路由后台的默认用户名和密码
2. 点「从 frps 导入」，勾选要加的盒子，点导入
3. 后台密码不一样的盒子，点「编辑」单独填

## 常用命令

| 操作 | 命令 |
|---|---|
| 重启 | `systemctl restart pw-panel` |
| 查看日志 | `journalctl -u pw-panel -n 50` |
| 查看面板密码 | `cat /opt/pw-panel/pw_panel_config.json` |
| 卸载 | `systemctl disable --now pw-panel && rm -rf /opt/pw-panel /etc/systemd/system/pw-panel.service` |

配置（包括各盒子的后台密码）只保存在服务器的 `/opt/pw-panel/pw_panel_config.json` 里，历史记录在 `/opt/pw-panel/pw_panel_history.jsonl`，都不会上传到别的地方。
