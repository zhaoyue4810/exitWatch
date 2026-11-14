#!/bin/zsh
cd -- "${0:A:h}" || exit 1
echo '启动后每三秒最多检测两个网站；错误 IP 立即关闭，超时按 2→3→5→3 个网站验证；并设为登录自启。'
/usr/bin/python3 watch.py start
read -k 1 '?按任意键关闭窗口。'
