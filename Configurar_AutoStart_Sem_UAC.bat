@echo off
title Configurar Inicializacao Silenciosa - Fulgor PCista
echo Solicitando privilegios de administrador...
powershell -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0configurar_autostart.ps1\"' -Verb RunAs"
