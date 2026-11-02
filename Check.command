#!/bin/zsh
cd -- "${0:A:h}" || exit 1
/usr/bin/python3 watch.py check
read -k 1 '?按任意键关闭窗口。'
