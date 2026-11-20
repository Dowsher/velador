@echo off
rem Velador: doble clic abre el menu. Tambien acepta: Velador.cmd revisar | vigilar | blindar | limpiar | estado
title Velador
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0velador.ps1" %*
