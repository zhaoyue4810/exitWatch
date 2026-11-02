#!/bin/zsh
cd -- "${0:A:h}" || exit 1
echo '启动后每秒最多检测两个网站；错误 IP 立即关闭，双站失败后换三站复核；并设为登录自启。'
/usr/bin/python3 watch.py start
read -k 1 '?按任意键关闭窗口。'
