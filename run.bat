@echo off
setlocal
:: 1. 設定編碼為 UTF-8，解決中文亂碼問題
chcp 65001 > nul

:: ==========================================
:: 設定目標檔案名稱 (請確認這裡跟您的 python 檔名一致)
set TARGET_FILE=authenticator.py
:: ==========================================

title Authenticator 啟動器
echo ==========================================
echo      正在檢查執行環境...
echo ==========================================

:: 2. 檢查是否有安裝 Python
python --version > nul 2>&1
if %errorlevel% neq 0 (
    color 4f
    echo [嚴重錯誤] 系統找不到 Python！
    echo 請前往 python.org 下載安裝，並記得勾選 "Add to PATH"。
    pause
    exit /b
)

:: 3. 自動補齊必要套件 (如果已安裝會自動跳過，速度很快)
echo [系統] 正在確保相依套件 (pyotp, cryptography, pywin32, winsdk)...
pip install pyotp cryptography pyperclip pywin32 winsdk --disable-pip-version-check > nul

if %errorlevel% neq 0 (
    echo [警告] 套件安裝過程出現問題，將嘗試強行啟動程式...
) else (
    echo [系統] 環境檢查完畢，準備啟動。
)

:: 4. 執行 Python 主程式
echo.
echo [啟動] 正在執行 %TARGET_FILE% ...
echo ---------------------------------------------------
python "%TARGET_FILE%"
:: 記錄程式結束代碼
set EXIT_CODE=%errorlevel%
echo ---------------------------------------------------

:: 5. 結束處理
if %EXIT_CODE% neq 0 (
    color 4f
    echo.
    echo [錯誤] 程式發生異常崩潰 (Exit Code: %EXIT_CODE%)
    echo 請查看上方的錯誤訊息 (Traceback)。
) else (
    echo.
    echo [結束] 程式已正常關閉。
)

:: 讓視窗暫停，不要馬上消失
pause