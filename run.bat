@echo off
title CyberShield - Web Security System
echo ========================================================
echo   CyberShield: Phishing Detection System Starting...
echo   Open your browser at: http://localhost:8085/
echo ========================================================
timeout /t 3 >nul
start "" "http://localhost:8085/"
where mvn >nul 2>&1
if %ERRORLEVEL% equ 0 (
    mvn spring-boot:run
) else if exist "C:\Users\USER\.gemini\antigravity\scratch\maven\apache-maven-3.9.6\bin\mvn.cmd" (
    "C:\Users\USER\.gemini\antigravity\scratch\maven\apache-maven-3.9.6\bin\mvn.cmd" spring-boot:run
) else (
    echo [ERROR] Apache Maven was not found on PATH.
    echo Please install Maven or open the project in VS Code / IntelliJ IDEA and click Run.
    pause
)
pause

