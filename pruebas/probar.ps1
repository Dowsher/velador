# Pruebas de Velador. Todo ocurre en una carpeta temporal con casos INOFENSIVOS (texto inerte);
# no toca la computadora real ni necesita permiso de administrador.
# Al terminar borra esa carpeta. Con -Conservar la deja, para poder inspeccionar los casos.
param([string]$Trabajo = '', [switch]$Conservar)
$ErrorActionPreference = 'Stop'
$raiz = Split-Path -Parent $PSScriptRoot
$vel = Join-Path $raiz 'velador.ps1'
$propia = -not $Trabajo
if ($propia) { $Trabajo = Join-Path $env:TEMP ('velador-pruebas-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
New-Item -ItemType Directory -Force -Path $Trabajo | Out-Null
$datos = Join-Path $Trabajo 'datos'

$script:ok = 0; $script:mal = 0
function Probar([string]$Nombre, [scriptblock]$Cond) {
    $r = $false
    try { $r = [bool](& $Cond) } catch { $Nombre += " [error: $($_.Exception.Message)]" }
    if ($r) { $script:ok++; Write-Host "  ok     $Nombre" } else { $script:mal++; Write-Host "  FALLA  $Nombre" -ForegroundColor Red }
}
function Texto([string]$Ruta, [string]$Contenido) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Ruta) | Out-Null
    [IO.File]::WriteAllText($Ruta, $Contenido)
}

# ---------------- casos de prueba ----------------
$cache = Join-Path $Trabajo 'fix\Microsoft\Windows'
$caches = Join-Path $cache 'Caches'; $webc = Join-Path $cache 'WebCache'
$carga = 'CurrentDomain.' + 'Load'; $hexa = 'SoapHex' + 'Binary'
Texto (Join-Path $caches 'build.cmd') "@echo off`r`nrem prueba inofensiva: este archivo nunca se ejecuta`r`n`"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`" `"%~dp0Falso.csproj`" /nologo`r`n"
Texto (Join-Path $caches 'Falso.csproj') '<Project><!-- prueba inofensiva de Velador --><Import Project="Compile.targets" /><!-- 2002,2027,144,0,3,0,0,0,4,0,0,0,255,255,0,0,184,0,0 --></Project>'
Texto (Join-Path $caches 'Falso.csproj.user') '<Project><PropertyGroup><Product>4d5a90000300000004000000ffff0000b8000000</Product></PropertyGroup></Project>'
Texto (Join-Path $caches 'Falso.Shared.props') '<Project><PropertyGroup><X>00aa00bb</X></PropertyGroup></Project>'
Texto (Join-Path $caches 'Compile.targets') ("<Project><!-- texto inerte para la prueba: [System.AppDomain]::$carga( $hexa --></Project>")
Texto (Join-Path $caches 'cversions.1.db') 'datos normales'
Texto (Join-Path $webc 'WebCacheV01.dat') 'datos normales'
foreach ($n in 'build.cmd', 'Falso.csproj', 'Falso.csproj.user', 'Falso.Shared.props', 'Compile.targets') {
    $it = Get-Item -LiteralPath (Join-Path $caches $n)
    $it.CreationTime = [datetime]'2001-02-03 19:56:07'
    $it.Attributes = [IO.FileAttributes]'Hidden, ReadOnly'
}
$limpio = Join-Path $Trabajo 'limpio'
Texto (Join-Path $limpio 'App.csproj') '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>'
$falso = Join-Path $Trabajo 'falso-instalador'
Texto (Join-Path $falso 'Setup.exe') 'no es un programa: es texto de prueba'
Texto (Join-Path $falso 'renpy\nada.txt') 'x'
Texto (Join-Path $falso 'lib\py3-windows-x86_64\nada.txt') 'x'
Texto (Join-Path $falso 'data\python-packages\sys_config\sys_check.py') "# prueba`r`ndef is_sandboxed(): return 'VBoxGuest'`r`n"
$clave = [Text.Encoding]::ASCII.GetBytes('81034149cd6f48c8821340204f92766e')
$json = [Text.Encoding]::UTF8.GetBytes('{"file_nm": "carga.E1", "pasw": "x", "exc_fl": "prueba.cmd", "snd_bx": false}')
for ($i = 0; $i -lt $json.Length; $i++) { $json[$i] = $json[$i] -bxor $clave[$i % $clave.Length] }
Texto (Join-Path $falso 'data\.QA3') ([Convert]::ToBase64String($json))
[IO.File]::WriteAllBytes((Join-Path $falso 'data\carga.E1'), (New-Object byte[] (2MB)))
$juego = Join-Path $Trabajo 'juego-real'
Texto (Join-Path $juego 'Juego.exe') 'texto'
Texto (Join-Path $juego 'renpy\nada.txt') 'x'
Texto (Join-Path $juego 'lib\py3-windows-x86_64\nada.txt') 'x'
Texto (Join-Path $juego 'game\script.rpyc') 'x'
[IO.File]::WriteAllBytes((Join-Path $juego 'game\archive.rpa'), (New-Object byte[] (2MB)))

# ---------------- sintaxis y carga ----------------
Write-Host ''
Write-Host 'Sintaxis y carga'
$err = $null; $tok = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($vel, [ref]$tok, [ref]$err)
Probar 'el archivo no tiene errores de sintaxis' { @($err).Count -eq 0 }
$b = [IO.File]::ReadAllBytes($vel)
Probar 'el archivo trae marca UTF-8 (acentos correctos en PowerShell 5.1)' { $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF }
. $vel funciones -SoloPruebas -Datos $datos
$script:CarpetasExtra = @($limpio, $falso, $juego)
$script:RaizCache = $cache
Probar 'las funciones cargan en modo de pruebas' { $script:Aislado -and (Get-Command Clasificar-Proceso -ErrorAction SilentlyContinue) }
Probar 'el apoyo nativo compila' { Cargar-Nativo }
Probar 'la foto de procesos trae datos' { @([VeladorNativo]::Nuevos()).Count -gt 20 }
Probar 'la segunda foto solo trae procesos nuevos' { @([VeladorNativo]::Nuevos()).Count -lt 20 }

# ---------------- reglas: órdenes y tareas ----------------
Write-Host ''
Write-Host 'Reglas de tareas programadas'
function Tarea($Nombre, $Exe, $Argu, $Oculta = $false, $Ruta = '\') {
    [pscustomobject]@{ Nombre = $Nombre; Ruta = $Ruta; Completa = ($Ruta.TrimEnd('\') + '\' + $Nombre); Autor = ''; Oculta = $Oculta; Activa = $true; Acciones = @([pscustomobject]@{ Exe = $Exe; Argumentos = $Argu }); AlIniciar = $true }
}
$sc = Separar-Comando '"C:\Program Files\x y\a.exe" --flag uno'
Probar 'separa una orden entre comillas' { $sc[0] -eq 'C:\Program Files\x y\a.exe' -and $sc[1] -eq '--flag uno' }
$sc = Separar-Comando ((Join-Path $env:WINDIR 'System32\cmd.exe') + ' /c echo hola')
Probar 'separa una orden sin comillas' { $sc[0] -like '*\cmd.exe' -and $sc[1] -eq '/c echo hola' }
$t = Evaluar-Tarea (Tarea 'conhost' 'C:\WINDOWS\system32\cmd.exe' '/c "C:\Users\x\AppData\Local\Microsoft\Windows\INetCache\build.cmd"' $true)
Probar 'la tarea real del ataque (conhost) sale GRAVE' { $t -and $t.Nivel -eq 'ALTO' }
Probar 'no marca el actualizador de OneDrive' { -not (Evaluar-Tarea (Tarea 'OneDrive Reporting' 'C:\Program Files\Microsoft OneDrive\OneDriveStandaloneUpdater.exe' '/reporting')) }
Probar 'no marca una tarea que corre un .cmd de Archivos de programa' { -not (Evaluar-Tarea (Tarea 'Activation-Renewal' '%ProgramFiles%\Activation-Renewal\Activation_task.cmd' 'Task')) }
Probar 'no marca node con un proyecto en Documentos' { -not (Evaluar-Tarea (Tarea 'Mi servidor' 'C:\Program Files\nodejs\node.exe' 'C:\Users\x\Documents\proyecto\server.mjs --production')) }
Probar 'no marca Firefox aunque mencione ProgramData' { -not (Evaluar-Tarea (Tarea 'Firefox Background Update' 'C:\Program Files\Mozilla Firefox\firefox.exe' '--MOZ_LOG_FILE C:\ProgramData\Mozilla\updates\x.moz_log --backgroundtask backgroundupdate')) }
Probar 'marca PowerShell con una orden codificada' { $x = Evaluar-Tarea (Tarea 'Actualizador' 'powershell.exe' ('-w hidden -enc ' + ('QUJD' * 20))); $x -and $x.Nivel -in 'ALTO', 'MEDIO' }
Probar 'marca una tarea que se disfraza de svchost' { $x = Evaluar-Tarea (Tarea 'svchost' 'C:\Program Files\X\x.exe' ''); $x -and $x.Nivel -eq 'MEDIO' }
Probar 'no marca svchost dentro de la carpeta de Microsoft' { -not (Evaluar-Tarea (Tarea 'svchost' 'C:\Program Files\X\x.exe' '' $false '\Microsoft\Windows\Algo\')) }

# ---------------- reglas: procesos ----------------
Write-Host ''
Write-Host 'Reglas del vigilante'
$ms = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'
$v = Clasificar-Proceso 'MSBuild.exe' $ms ('"' + $ms + '" "C:\Users\x\AppData\Local\Microsoft\Windows\Caches\Zxing.csproj" /nologo /v:q') 'cmd.exe' 'cmd.exe /c "C:\Users\x\AppData\Local\Microsoft\Windows\Caches\build.cmd" /launched'
Probar 'detiene MSBuild sobre un proyecto en carpeta de caché (el ataque real)' { $v -and $v.Nivel -eq 'ALTO' -and $v.Matar }
$v = Clasificar-Proceso 'MSBuild.exe' $ms ('"' + $ms + '" Zxing.csproj /nologo') 'cmd.exe' 'C:\WINDOWS\system32\cmd.exe /c "C:\Users\x\AppData\Local\Temp\tmp-12345-abcdefABCDEF\build.cmd" /launched'
Probar 'detiene MSBuild con proyecto relativo si lo lanzó un .cmd de Temp' { $v -and $v.Matar }
Probar 'deja en paz a MSBuild sobre un proyecto normal' { -not (Clasificar-Proceso 'MSBuild.exe' $ms ('"' + $ms + '" C:\src\app\app.csproj /t:Build') 'powershell.exe' '') }
$v = Clasificar-Proceso 'cmd.exe' 'C:\Windows\System32\cmd.exe' 'cmd.exe /c "C:\Users\x\AppData\Local\Temp\tmp-1\a.cmd" /launched' 'conhost.exe' '"C:\WINDOWS\System32\conhost.exe" --headless cmd.exe /c "C:\Users\x\AppData\Local\Temp\tmp-1\a.cmd" /launched'
Probar 'detiene la orden invisible con conhost --headless (el ataque real)' { $v -and $v.Matar -and $v.Raiz -eq 'padre' }
Probar 'deja en paz a las terminales normales (conhost con --server)' { -not (Clasificar-Proceso 'cmd.exe' 'C:\Windows\System32\cmd.exe' 'cmd.exe /d /s /c "npx -y algo"' 'conhost.exe' '\\?\C:\WINDOWS\system32\conhost.exe --headless --width 99 --height 85 --signal 0x54c --server 0x540') }
Probar 'deja en paz a la consola normal' { -not (Clasificar-Proceso 'cmd.exe' 'C:\Windows\System32\cmd.exe' 'cmd.exe' 'conhost.exe' '\??\C:\WINDOWS\system32\conhost.exe 0x4') }
$v = Clasificar-Proceso 'forfiles.exe' 'C:\Windows\System32\forfiles.exe' 'forfiles.exe /p C:\Users\x\AppData\Local\Temp\tmp-12345-abcdefABCDEF /m T.x1 /c "cmd /c ren @file T.bat && call T.bat"' 'Setup.exe' ''
Probar 'detiene forfiles usado para ejecutar a escondidas (el ataque real)' { $v -and $v.Matar }
Probar 'deja en paz a forfiles borrando archivos viejos' { -not (Clasificar-Proceso 'forfiles.exe' 'C:\Windows\System32\forfiles.exe' 'forfiles /p C:\Users\x\AppData\Local\Temp /d -30 /c "cmd /c del @path"' 'cmd.exe' '') }
$ra = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe'
Probar 'detiene RegAsm abierto sin instrucciones' { $x = Clasificar-Proceso 'RegAsm.exe' $ra ('"' + $ra + '"') 'x.exe' ''; $x -and $x.Matar }
Probar 'deja en paz a RegAsm registrando una biblioteca instalada' { -not (Clasificar-Proceso 'RegAsm.exe' $ra ('"' + $ra + '" /codebase "C:\Program Files\App\x.dll"') 'setup.exe' '') }
Probar 'detiene un .js descargado' { $x = Clasificar-Proceso 'wscript.exe' 'C:\Windows\System32\wscript.exe' '"C:\Windows\System32\WScript.exe" "C:\Users\x\Downloads\factura.js"' 'explorer.exe' ''; $x -and $x.Matar }
Probar 'deja en paz a un .vbs de un programa instalado' { -not (Clasificar-Proceso 'wscript.exe' 'C:\Windows\System32\wscript.exe' '"C:\Windows\System32\wscript.exe" "C:\Program Files\App\run.vbs"' 'app.exe' '') }
Probar 'detiene mshta con una dirección de internet' { $x = Clasificar-Proceso 'mshta.exe' 'C:\Windows\System32\mshta.exe' 'mshta.exe https://ejemplo.invalid/a.hta' 'cmd.exe' ''; $x -and $x.Matar }
Probar 'detiene un programa que corre desde la caché de Windows' { $x = Clasificar-Proceso 'x.exe' 'C:\Users\x\AppData\Local\Microsoft\Windows\INetCache\x.exe' '' '' ''; $x -and $x.Matar }
Probar 'avisa al crear una tarea programada sospechosa' { $x = Clasificar-Proceso 'schtasks.exe' 'C:\Windows\System32\schtasks.exe' 'schtasks /create /tn conhost /tr "cmd.exe /c C:\Users\x\AppData\Local\Temp\b.cmd" /sc onlogon' 'x.exe' ''; $x -and $x.Nivel -eq 'ALTO' -and -not $x.Matar }
Probar 'no dice nada de un programa cualquiera' { -not (Clasificar-Proceso 'notepad.exe' 'C:\Windows\System32\notepad.exe' 'notepad.exe C:\Users\x\Downloads\nota.txt' 'explorer.exe' '') }

# ---------------- archivos ----------------
Write-Host ''
Write-Host 'Reconocer archivos'
Probar 'reconoce el proyecto cargador' { @(Buscar-IndicadoresProyecto (Join-Path $caches 'Compile.targets') | Where-Object { $_.Fuerte }).Count -ge 1 }
Probar 'reconoce un programa escondido en hexadecimal' { @(Buscar-IndicadoresProyecto (Join-Path $caches 'Falso.csproj.user') | Where-Object { $_.Fuerte }).Count -ge 1 }
Probar 'reconoce un programa escondido como lista de números' { @(Buscar-IndicadoresProyecto (Join-Path $caches 'Falso.csproj') | Where-Object { $_.Fuerte }).Count -ge 1 }
Probar 'un proyecto normal sale limpio' { @(Buscar-IndicadoresProyecto (Join-Path $limpio 'App.csproj')).Count -eq 0 }
$f = Probar-InstaladorFalso $falso
Probar 'reconoce el instalador falso' { $f -and $f.Fuerte }
Probar 'descifra la configuración oculta del instalador falso' { (@($f.Evidencia) -join ' ') -match 'prueba\.cmd' }
Probar 'un juego Ren''Py de verdad sale limpio' { -not (Probar-InstaladorFalso $juego) }
Probar 'el buscador rápido encuentra los proyectos' { @(Listar-Archivos @($Trabajo) $script:ExtProyecto 8).Count -ge 5 }

# ---------------- revisión, cuarentena y restauración ----------------
Write-Host ''
Write-Host 'Revisión completa, cuarentena y restauración'
$h = @(Ejecutar-Revision -Silencioso)
$graves = @($h | Where-Object { $_.Nivel -eq 'ALTO' })
Probar 'la revisión encuentra exactamente los 2 casos graves' { $graves.Count -eq 2 }
$hc = $graves | Where-Object { $_.Donde -eq $caches } | Select-Object -First 1
Probar 'el caso de la caché incluye los 5 archivos del cargador' { $hc -and @($hc.Archivos).Count -eq 5 }
Probar 'nota que los archivos están ocultos y con fecha falsa' { $e = (@($hc.Evidencia) -join ' | '); $e -match 'ocultos' -and $e -match 'fecha de creación falsa' }
Probar 'no marca el proyecto limpio, el juego real ni los datos normales' { -not (@($h | ForEach-Object { $_.Donde + ' ' + (@($_.Archivos) -join ' ') }) -match 'limpio|juego-real|WebCache|cversions') }
$html = Join-Path $Trabajo 'informe.html'
Escribir-InformeHtml $h $html
Probar 'escribe el informe' { (Test-Path -LiteralPath $html) -and ((Get-Content -LiteralPath $html -Raw -Encoding UTF8) -match 'hallazgo\(s\) graves') }

$script:Simular = $true
Ejecutar-Limpieza *> $null
Probar 'en simulación no mueve nada' { (Test-Path -LiteralPath (Join-Path $caches 'build.cmd')) -and (Test-Path -LiteralPath $falso) }
$script:Simular = $false; $script:Si = $true
Ejecutar-Limpieza *> $null
Probar 'la limpieza saca los 5 archivos de la caché' { @(Get-ChildItem -LiteralPath $caches -Force -File).Count -eq 1 }
Probar 'la limpieza saca la carpeta del instalador falso' { -not (Test-Path -LiteralPath $falso) }
Probar 'deja intactos los datos normales' { (Test-Path -LiteralPath (Join-Path $caches 'cversions.1.db')) -and (Test-Path -LiteralPath (Join-Path $webc 'WebCacheV01.dat')) -and (Test-Path -LiteralPath (Join-Path $limpio 'App.csproj')) }
Probar 'después de limpiar ya no hay casos graves' { @(Ejecutar-Revision -Silencioso | Where-Object { $_.Nivel -eq 'ALTO' }).Count -eq 0 }
Probar 'lo movido quedó en cuarentena y sin extensión ejecutable' { @(Get-ChildItem -LiteralPath (Join-Path $datos 'cuarentena') -Recurse -File -Filter '*.cuarentena').Count -eq 5 }
Ejecutar-Restauracion *> $null
Probar 'restaurar regresa los archivos y la carpeta' { @(Get-ChildItem -LiteralPath $caches -Force -File).Count -eq 6 -and (Test-Path -LiteralPath (Join-Path $falso 'data\.QA3')) }
Probar 'restaurar devuelve los atributos y la fecha' { $it = Get-Item -LiteralPath (Join-Path $caches 'build.cmd') -Force; (($it.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) -and $it.CreationTime.Year -eq 2001 }
$script:Si = $false

# ---------------- blindaje (sin tocar el sistema) ----------------
Write-Host ''
Write-Host 'Blindaje'
$progs = @(Lista-ProgramasCortafuegos)
Probar 'la lista del cortafuegos tiene programas y todos existen' { $progs.Count -gt 20 -and @($progs | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -eq 0 }
Probar 'incluye el MSBuild que usó el ataque' { $progs -contains (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe') }
Probar 'no le quita internet a PowerShell, cmd, rundll32 ni al navegador' { @($progs | Where-Object { $_ -match '(?i)\\(powershell|pwsh|cmd|rundll32|explorer|msedge|chrome)\.exe$' }).Count -eq 0 }
Probar 'cada regla del cortafuegos tiene un nombre distinto' { @($progs | ForEach-Object { Nombre-Regla $_ } | Select-Object -Unique).Count -eq $progs.Count }
Probar 'las reglas del antivirus tienen identificador válido y único' { @($script:ReglasASR | Where-Object { $_.Id -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$' }).Count -eq 0 -and @($script:ReglasASR | ForEach-Object { $_.Id } | Select-Object -Unique).Count -eq $script:ReglasASR.Count }
Probar 'Windows acepta los parámetros que usa el blindaje' {
    $mp = (Get-Command Set-MpPreference).Parameters; $fw = (Get-Command New-NetFirewallRule).Parameters
    @('PUAProtection', 'CloudBlockLevel', 'CloudExtendedTimeout', 'MAPSReporting', 'AttackSurfaceReductionRules_Ids', 'AttackSurfaceReductionRules_Actions', 'DisableRealtimeMonitoring' | Where-Object { -not $mp.ContainsKey($_) }).Count -eq 0 -and @('DisplayName', 'Group', 'Description', 'Direction', 'Action', 'Program', 'Profile' | Where-Object { -not $fw.ContainsKey($_) }).Count -eq 0
}
$reg = 'HKCU:\Software\VeladorPrueba'
Aplicar-BlindajeUsuario -RaizReg $reg -Clases @('PruebaFile') *> $null
Probar 'el cambio de archivos de órdenes se aplica (en una clave de prueba)' { (Get-ItemProperty -Path "$reg\PruebaFile\Shell\Open\Command").'(default)' -match 'notepad\.exe' }
Quitar-BlindajeUsuario -RaizReg $reg -Clases @('PruebaFile') *> $null
Probar 'y se deshace sin dejar rastro' { -not (Test-Path -Path "$reg\PruebaFile") }
Remove-Item -Path $reg -Recurse -Force -ErrorAction SilentlyContinue
$script:Simular = $true
$plan = (Mostrar-PlanBlindaje *>&1 | Out-String)
$script:Simular = $false
Probar 'la simulación del blindaje lista cada cambio' { $plan -match 'New-NetFirewallRule' -and $plan -match 'Set-MpPreference' -and $plan -match 'JSFile' }

Write-Host ''
Write-Host ("RESULTADO: {0} pruebas bien, {1} con falla" -f $script:ok, $script:mal)
# Los casos imitan la forma del ataque: si se quedaran en la carpeta temporal, una revisión real los marcaría.
# Solo se borra la carpeta que crearon las pruebas, nunca una que haya elegido quien las corre.
if ($propia -and -not $Conservar) { Remove-Item -LiteralPath $Trabajo -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path -LiteralPath $Trabajo) { Write-Host ("Carpeta de trabajo: {0}" -f $Trabajo) }
if ($script:mal -gt 0) { exit 1 }
