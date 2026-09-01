@echo off
title Aegis AI Antivirus - Instalador y Lanzador
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ================================================
echo    Aegis AI Antivirus - Lanzador Automatico
echo    Monitorizacion en tiempo real con IA
echo ================================================
echo.

rem ------- Verificar Node.js -------
where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js NO esta instalado en este equipo.
  echo.
  echo Descargalo desde: https://nodejs.org/
  echo Selecciona la version LTS e instala con opciones por defecto.
  echo.
  pause
  exit /b 1
)

for /f "tokens=1 delims=" %%v in ('node -v') do set NODEV=%%v
echo [OK] Node.js detectado: %NODEV%

rem ------- Instalar dependencias en el primer inicio -------
if not exist "node_modules" (
  echo.
  echo [INFO] Primera ejecucion detectada. Instalando dependencias...
  echo Esto puede tardar unos minutos.
  echo.
  call npm install
  if errorlevel 1 (
    echo.
    echo [ERROR] Fallo la instalacion de dependencias.
    echo Revisa tu conexion a Internet e intentalo de nuevo.
    pause
    exit /b 1
  )
  echo.
  echo [OK] Dependencias instaladas correctamente.
)

rem ------- Asegurar binario de Electron (si npm bloqueo el postinstall) -------
if not exist "node_modules\electron\dist\electron.exe" (
  echo [INFO] Completando instalacion del binario de Electron...
  if exist "node_modules\electron\install.js" (
    node "node_modules\electron\install.js"
  )
)
if not exist "node_modules\electron\dist\electron.exe" (
  echo.
  echo [ERROR] El binario de Electron no pudo descargarse.
  echo Revisa tu conexion a Internet e intentalo de nuevo.
  pause
  exit /b 1
)

rem ------- Verificar derechos de administrador -------
net session >nul 2>nul
if errorlevel 1 (
  echo.
  echo [AVISO] La aplicacion se abrira sin permisos de administrador.
  echo Algunas funciones como Firewall, apertura de puertos y
  echo bloqueo de conexiones requieren ejecutarse como administrador.
  echo Puedes cerrar la app y pulsar "Ejecutar como administrador" en el .bat.
  echo.
)

echo.
echo [OK] Iniciando Aegis AI Antivirus...
echo.

call npx electron .
if errorlevel 1 (
  echo.
  echo [ERROR] No se pudo iniciar la aplicacion.
  echo Verifica que Node.js este correctamente instalado.
  pause
)

endlocal