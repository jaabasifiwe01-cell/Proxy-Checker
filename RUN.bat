@echo off
title Proxy Pro Advanced v1.0.7
cd /d "%~dp0"
if not exist node_modules ( call npm install )
node proxy-pro.js
pause
