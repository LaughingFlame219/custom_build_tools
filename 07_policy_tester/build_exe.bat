@echo off
rem Windows用: 単一exeを作る (要 pip install pyinstaller)
pyinstaller --onefile --name PolicyTester --hidden-import scenario_gen --hidden-import fg2scenario --hidden-import palo2scenario --hidden-import vrouter_gen trafficgen.py
echo dist\PolicyTester.exe ができました。ダブルクリックでブラウザUIが開きます。
