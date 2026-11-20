<#
  VELADOR 1.0
  Guardia contra instaladores falsos y programas que se cargan a escondidas en Windows.

  Doble clic en Velador.cmd abre el menú. También se puede llamar directo:
    velador.ps1 revisar      Revisa la computadora y abre un informe. No cambia nada.
    velador.ps1 vigilar      Enciende el vigilante (icono junto al reloj).
    velador.ps1 blindar      Aplica el blindaje (pide permiso de administrador). Con -Simular solo lo muestra.
    velador.ps1 desblindar   Deshace el blindaje.
    velador.ps1 limpiar      Manda a cuarentena lo que la revisión marcó como grave (pide confirmación).
    velador.ps1 restaurar    Regresa a su lugar la última cuarentena.
    velador.ps1 estado       Muestra cómo está todo.

  Funciona con el PowerShell que ya trae Windows 10 y 11. No instala nada.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Modo = 'menu',
    [switch]$Simular,
    [switch]$Si,
    [switch]$SinAbrir,
    [switch]$Consola,
    [switch]$Elevado,
    [switch]$SoloPruebas,
    [int]$Segundos = 0,
    [string[]]$CarpetasExtra = @(),
    [string]$RaizCache = '',
    [string]$Datos = ''
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

$script:Version = '1.0'
$script:Yo = $MyInvocation.MyCommand.Path
if (-not $Datos) { $Datos = Join-Path $env:LOCALAPPDATA 'Velador' }
if (-not (Test-Path -LiteralPath $Datos)) { New-Item -ItemType Directory -Force -Path $Datos | Out-Null }
$script:Datos = $Datos
$script:Registro = Join-Path $Datos 'registro.log'
$script:Aislado = [bool]$SoloPruebas
$script:Simular = [bool]$Simular
$script:Si = [bool]$Si
$script:SinAbrir = [bool]$SinAbrir
$script:Consola = [bool]$Consola
$script:Elevado = [bool]$Elevado
$script:Segundos = $Segundos
$script:CarpetasExtra = @($CarpetasExtra | Where-Object { $_ })
$script:RaizCache = $RaizCache
$script:Nativo = $false
$script:Icono = $null

# ---------------------------------------------------------------------------------------------
#  Reglas (lo que Velador considera sospechoso)
# ---------------------------------------------------------------------------------------------
$script:RxRutaAlta = '(?i)\\(AppData\\(Local|Roaming|LocalLow)|Temp|Downloads|Descargas|Users\\Public)\\'
$script:RxRutaMedia = '(?i)\\ProgramData\\'
$script:RxCacheWin = '(?i)\\Microsoft\\Windows\\(Caches|WebCache|INetCache|History|INetCookies)\\'
$script:RxLanzado = '(?i)\\(Downloads|Descargas|Desktop|Escritorio|Temp)\\'
$script:RxOfuscado = '(?i)(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}|FromBase64' + 'String|Download' + 'String|Download' + 'File|\bI' + 'EX\b|Invoke-Exp' + 'ression)'

$script:Interpretes = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'conhost.exe', 'forfiles.exe', 'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'certutil.exe', 'bitsadmin.exe')
$script:HostsNet = @('msbuild.exe', 'regasm.exe', 'regsvcs.exe', 'installutil.exe', 'addinprocess.exe', 'addinprocess32.exe', 'aspnet_compiler.exe', 'caspol.exe', 'jsc.exe', 'applaunch.exe', 'microsoft.workflow.compiler.exe', 'ilasm.exe')
$script:VigilarNombre = @('forfiles.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'schtasks.exe')
$script:NombresSistema = @('conhost', 'svchost', 'csrss', 'lsass', 'smss', 'services', 'winlogon', 'explorer', 'dllhost', 'taskhostw', 'taskhost', 'runtimebroker', 'sihost', 'spoolsv', 'wininit', 'dwm', 'ctfmon', 'fontdrvhost', 'searchindexer', 'audiodg', 'wudfhost', 'rundll32', 'cmd', 'powershell', 'msbuild', 'system', 'wuauclt', 'sppsvc', 'securityhealthservice', 'msmpeng', 'userinit', 'taskmgr', 'wmiprvse')
$script:ExtProyecto = @('.csproj', '.vbproj', '.fsproj', '.proj', '.targets', '.props', '.user', '.tasks', '.msbuild', '.build')
$script:ExtEjecutable = @('.cmd', '.bat', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.sct', '.exe', '.dll', '.scr', '.pif', '.com', '.cpl', '.msi', '.jar', '.py', '.lnk') + $script:ExtProyecto
$script:ClasesScript = @('JSFile', 'JSEFile', 'VBSFile', 'VBEFile', 'WSFFile', 'WSHFile', 'htafile')

# Reglas de reducción de superficie de ataque de Microsoft Defender. Accion: 1 = bloquear, 2 = solo registrar.
$script:ReglasASR = @(
    @{ Id = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; Accion = 1; Nombre = 'Bloquear scripts ofuscados' },
    @{ Id = 'd3e037e1-3eb8-44c8-a917-57927947596d'; Accion = 1; Nombre = 'Bloquear que JavaScript o VBScript lancen programas descargados' },
    @{ Id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Accion = 1; Nombre = 'Bloquear el robo de credenciales de Windows (LSASS)' },
    @{ Id = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; Accion = 1; Nombre = 'Bloquear permanencia por suscripciones WMI' },
    @{ Id = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Accion = 1; Nombre = 'Bloquear programas sin firma que corren desde USB' },
    @{ Id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Accion = 1; Nombre = 'Bloquear controladores firmados vulnerables' },
    @{ Id = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; Accion = 1; Nombre = 'Usar protección avanzada contra ransomware' },
    @{ Id = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Accion = 1; Nombre = 'Bloquear ejecutables que llegan por correo' },
    @{ Id = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'; Accion = 1; Nombre = 'Bloquear copias o imitaciones de herramientas de Windows' },
    @{ Id = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; Accion = 1; Nombre = 'Bloquear que Office abra otros programas' },
    @{ Id = '3b576869-a4ec-4529-8536-b80a7769e899'; Accion = 1; Nombre = 'Bloquear que Office cree ejecutables' },
    @{ Id = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Accion = 1; Nombre = 'Bloquear que Office inyecte código en otros procesos' },
    @{ Id = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; Accion = 1; Nombre = 'Bloquear que Adobe Reader abra otros programas' },
    @{ Id = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; Accion = 2; Nombre = 'Llamadas a Windows desde macros de Office (solo registrar)' },
    @{ Id = '01443614-cd74-433a-b99e-2ecdc07bfc25'; Accion = 2; Nombre = 'Programas desconocidos o muy nuevos (solo registrar)' },
    @{ Id = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; Accion = 2; Nombre = 'Procesos creados por PSExec o WMI (solo registrar)' }
)

# ---------------------------------------------------------------------------------------------
#  Utilidades
# ---------------------------------------------------------------------------------------------
function Escribir-Registro([string]$Nivel, [string]$Texto) {
    $linea = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Nivel, $Texto
    try { Add-Content -LiteralPath $script:Registro -Value $linea -Encoding UTF8 -ErrorAction Stop } catch {}
}

function Es-Admin {
    try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { return $false }
}

function Leer-Config {
    $c = [pscustomobject]@{ SoloAvisar = $false; Permitidos = @() }
    $p = Join-Path $script:Datos 'config.json'
    if (Test-Path -LiteralPath $p) {
        try {
            $j = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $j.SoloAvisar) { $c.SoloAvisar = [bool]$j.SoloAvisar }
            if ($j.Permitidos) { $c.Permitidos = @($j.Permitidos) }
        } catch {}
    }
    return $c
}

function Esta-Permitido([string]$Texto) {
    if (-not $Texto) { return $false }
    foreach ($p in @($script:Config.Permitidos)) {
        if ($p -and $Texto.ToLower().Contains(([string]$p).ToLower())) { return $true }
    }
    return $false
}

function Confirmar([string]$Pregunta) {
    if ($script:Si -and $script:Aislado) { return $true }
    try { $r = Read-Host ("{0} (S/N)" -f $Pregunta); return ($r -match '^\s*(s|si|sí|y|yes)\s*$') } catch { return $false }
}

# Convierte una lista a texto JSON siempre como lista (PowerShell 5.1 falla con algunas listas si no se hace así).
function A-Json($Lista, [int]$Profundidad = 6) {
    $arr = @($Lista | ForEach-Object { $_ })
    if ($arr.Count -eq 0) { return '[]' }
    $j = ($arr | ConvertTo-Json -Depth $Profundidad)
    if ($arr.Count -eq 1) { $j = "[`r`n$j`r`n]" }
    return $j
}

function Pausa-Final {
    try { [void](Read-Host 'Presiona Enter para cerrar') } catch {}
}

# Windows a veces entrega la misma carpeta con su nombre corto (PROGRA~1) y otras con el largo.
# Para no contar dos veces el mismo lugar, las carpetas se pasan siempre a la forma larga.
function Ruta-Larga([string]$Ruta) {
    if (-not $Ruta -or $Ruta.IndexOf('~') -lt 0) { return $Ruta }
    try { if (Test-Path -LiteralPath $Ruta) { return [IO.Path]::GetFullPath($Ruta) } } catch {}
    return $Ruta
}

function Cargar-Nativo {
    if ('VeladorNativo' -as [type]) { return $true }
    $cs = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class VeladorNativo
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize; public uint cntUsage; public uint th32ProcessID; public IntPtr th32DefaultHeapID;
        public uint th32ModuleID; public uint cntThreads; public uint th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32FirstW(IntPtr h, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32NextW(IntPtr h, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder sb, ref uint size);
    [DllImport("kernel32.dll")] private static extern bool GetProcessTimes(IntPtr h, out long creacion, out long salida, out long nucleo, out long usuario);

    private static Dictionary<uint, string[]> anterior = new Dictionary<uint, string[]>();

    // Foto de los procesos: id -> [idPadre, nombre]
    private static Dictionary<uint, string[]> Foto()
    {
        var d = new Dictionary<uint, string[]>();
        IntPtr h = CreateToolhelp32Snapshot(2, 0);
        if (h == IntPtr.Zero || h == new IntPtr(-1)) return d;
        try
        {
            var e = new PROCESSENTRY32W();
            e.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));
            if (Process32FirstW(h, ref e))
            {
                do { d[e.th32ProcessID] = new string[] { e.th32ParentProcessID.ToString(), e.szExeFile ?? "" }; }
                while (Process32NextW(h, ref e));
            }
        }
        finally { CloseHandle(h); }
        return d;
    }

    public static string Ruta(uint pid)
    {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return "";
        try
        {
            var sb = new StringBuilder(1024); uint n = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(h, 0, sb, ref n) ? sb.ToString() : "";
        }
        finally { CloseHandle(h); }
    }

    public static long Inicio(uint pid)
    {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return 0;
        try { long c, s, k, u; return GetProcessTimes(h, out c, out s, out k, out u) ? c : 0; }
        finally { CloseHandle(h); }
    }

    // Procesos que no estaban en la foto anterior: [id, idPadre, nombre, ruta, nombrePadre, nombreAbuelo]
    public static List<string[]> Nuevos()
    {
        var ahora = Foto(); var r = new List<string[]>();
        foreach (var kv in ahora)
        {
            if (kv.Key == 0) continue;
            string[] prev;
            if (anterior.TryGetValue(kv.Key, out prev) && prev[0] == kv.Value[0] && prev[1] == kv.Value[1]) continue;
            uint ppid = 0; uint.TryParse(kv.Value[0], out ppid);
            string padre = "", abuelo = ""; string[] p;
            if (ppid != 0 && ahora.TryGetValue(ppid, out p))
            {
                long ti = Inicio(kv.Key), tp = Inicio(ppid);
                if (ti == 0 || tp == 0 || tp <= ti)
                {
                    padre = p[1];
                    uint gp = 0; uint.TryParse(p[0], out gp); string[] g;
                    if (gp != 0 && ahora.TryGetValue(gp, out g)) abuelo = g[1];
                }
            }
            r.Add(new string[] { kv.Key.ToString(), kv.Value[0], kv.Value[1], Ruta(kv.Key), padre, abuelo });
        }
        anterior = ahora;
        return r;
    }

    // Hijos, nietos... de un proceso. Solo cuenta los que nacieron después que su padre (evita confusiones por números reutilizados).
    public static List<uint> Descendientes(uint raiz)
    {
        var f = Foto(); var r = new List<uint>(); var cola = new Queue<uint>(); cola.Enqueue(raiz);
        var t = new Dictionary<uint, long>(); t[raiz] = Inicio(raiz);
        while (cola.Count > 0)
        {
            uint x = cola.Dequeue(); string xs = x.ToString(); long tx = t[x];
            foreach (var kv in f)
            {
                if (kv.Key == 0 || kv.Key == raiz || kv.Value[0] != xs || r.Contains(kv.Key)) continue;
                long tk = Inicio(kv.Key);
                if (tk == 0 || tx == 0 || tk < tx) continue;
                r.Add(kv.Key); t[kv.Key] = tk; cola.Enqueue(kv.Key);
            }
        }
        return r;
    }

    // Recorre carpetas rápido y devuelve solo los archivos con las extensiones pedidas.
    public static List<string> Archivos(string[] raices, string[] extensiones, int profundidad, string[] saltar)
    {
        var ext = new HashSet<string>(extensiones, StringComparer.OrdinalIgnoreCase);
        var omitir = new HashSet<string>(saltar ?? new string[0], StringComparer.OrdinalIgnoreCase);
        var r = new List<string>(); var pila = new Stack<KeyValuePair<string, int>>();
        foreach (var x in raices) if (!string.IsNullOrEmpty(x) && Directory.Exists(x)) pila.Push(new KeyValuePair<string, int>(x, 0));
        while (pila.Count > 0)
        {
            var it = pila.Pop();
            try
            {
                foreach (var f in Directory.EnumerateFiles(it.Key))
                {
                    try { if (ext.Contains(Path.GetExtension(f))) r.Add(f); } catch { }
                }
                if (it.Value < profundidad)
                {
                    foreach (var d in Directory.EnumerateDirectories(it.Key))
                    {
                        try
                        {
                            if (omitir.Contains(Path.GetFileName(d))) continue;
                            if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue;
                            pila.Push(new KeyValuePair<string, int>(d, it.Value + 1));
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
        return r;
    }
}
'@
    try { Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop; return $true }
    catch { Escribir-Registro 'AVISO' ('Sin apoyo nativo, se usa el modo lento: ' + $_.Exception.Message); return $false }
}

function Listar-Archivos([string[]]$Raices, [string[]]$Extensiones, [int]$Profundidad) {
    $validas = @($Raices | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | ForEach-Object { Ruta-Larga $_ } | Select-Object -Unique)
    $final = @()
    foreach ($r in $validas) {
        $dentro = $false
        foreach ($o in $validas) { if ($o -ne $r -and $r.ToLower().StartsWith($o.ToLower().TrimEnd('\') + '\')) { $dentro = $true } }
        if (-not $dentro) { $final += $r }
    }
    if ($final.Count -eq 0) { return @() }
    if (Cargar-Nativo) { return @([VeladorNativo]::Archivos([string[]]$final, [string[]]$Extensiones, $Profundidad, [string[]]@('node_modules', '.git'))) }
    $res = @()
    foreach ($r in $final) {
        $res += @(Get-ChildItem -LiteralPath $r -Recurse -Depth ([Math]::Min($Profundidad, 6)) -Force -File -ErrorAction SilentlyContinue | Where-Object { $Extensiones -contains $_.Extension.ToLower() } | ForEach-Object { $_.FullName })
    }
    return $res
}

# Busca dentro de un archivo de proyecto las señas de un cargador escondido.
function Buscar-IndicadoresProyecto([string]$Ruta) {
    $r = @()
    $t = $null
    try {
        $fi = New-Object System.IO.FileInfo($Ruta)
        if (-not $fi.Exists -or $fi.Length -lt 16 -or $fi.Length -gt 64MB) { return $r }
        $b = [System.IO.File]::ReadAllBytes($Ruta)
        if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { $t = [System.Text.Encoding]::Unicode.GetString($b) }
        else { $t = [System.Text.Encoding]::GetEncoding(28591).GetString($b) }
    } catch { return $r }
    $oi = [System.StringComparison]::OrdinalIgnoreCase
    $or = [System.StringComparison]::Ordinal
    if ($t.IndexOf(('CurrentDomain.' + 'Load'), $oi) -ge 0 -or $t.IndexOf(('Assembly]::' + 'Load'), $oi) -ge 0) {
        $r += [pscustomobject]@{ Texto = 'le ordena a MSBuild cargar un programa directo en la memoria'; Fuerte = $true }
    }
    if ($t.IndexOf(('SoapHex' + 'Binary'), $oi) -ge 0) {
        $r += [pscustomobject]@{ Texto = 'convierte texto hexadecimal en un programa'; Fuerte = $true }
    }
    if ($t.IndexOf('4d5a9000030000000400', $oi) -ge 0) {
        $r += [pscustomobject]@{ Texto = 'trae un programa de Windows escondido como texto hexadecimal'; Fuerte = $true }
    }
    if ($t.IndexOf(',144,0,3,0,0,0,4,0,0,0,255,255,0,0,184,0', $or) -ge 0) {
        $r += [pscustomobject]@{ Texto = 'trae un programa de Windows escondido como una lista de números'; Fuerte = $true }
    }
    if ($t.IndexOf('TVqQAAMAAAAEAAAA', $or) -ge 0) {
        $r += [pscustomobject]@{ Texto = 'trae un programa de Windows escondido en base64'; Fuerte = $false }
    }
    return $r
}

function Extraer-Rutas([string]$Cl) {
    $r = @()
    foreach ($m in [regex]::Matches([string]$Cl, '"([A-Za-z]:\\[^"]+)"|([A-Za-z]:\\\S+)')) {
        if ($m.Groups[1].Success) { $r += $m.Groups[1].Value } else { $r += $m.Groups[2].Value }
    }
    return $r
}

# Parte una orden en programa y resto: devuelve dos textos.
function Separar-Comando([string]$Linea) {
    $l = [Environment]::ExpandEnvironmentVariables(([string]$Linea).Trim())
    if (-not $l) { return @('', '') }
    if ($l.StartsWith('"')) {
        $i = $l.IndexOf('"', 1)
        if ($i -gt 0) { return @($l.Substring(1, $i - 1), $l.Substring($i + 1).Trim()) }
    }
    $partes = @($l -split '\s+')
    for ($n = 1; $n -le $partes.Count; $n++) {
        $cand = ($partes[0..($n - 1)] -join ' ')
        if ($cand -match '(?i)\.(exe|com|cmd|bat|ps1|vbs|js|msi|scr)$') {
            $ok = $false; try { $ok = Test-Path -LiteralPath $cand -PathType Leaf } catch {}
            if ($ok) {
                $resto = ''; if ($n -lt $partes.Count) { $resto = ($partes[$n..($partes.Count - 1)] -join ' ') }
                return @($cand, $resto)
            }
        }
    }
    $resto = ''; if ($partes.Count -gt 1) { $resto = ($partes[1..($partes.Count - 1)] -join ' ') }
    return @($partes[0], $resto)
}

# Califica una orden (programa + argumentos). Más puntos = más sospechosa.
function Evaluar-Comando([string]$Exe, [string]$Argumentos) {
    $puntos = 0; $ev = @()
    $exe = [Environment]::ExpandEnvironmentVariables(([string]$Exe).Trim().Trim('"'))
    $arg = [Environment]::ExpandEnvironmentVariables([string]$Argumentos)
    $nom = ''; try { $nom = [IO.Path]::GetFileName($exe).ToLower() } catch { $nom = $exe.ToLower() }
    if ($nom -and $nom -notmatch '\.\w+$') { $nom = "$nom.exe" }
    $todo = "$exe $arg"
    if ($script:Interpretes -contains $nom) {
        if ($todo -match $script:RxCacheWin) { $puntos += 5; $ev += "usa $nom para ejecutar algo guardado en una carpeta de caché de Windows" }
        elseif ($arg -match $script:RxRutaAlta) { $puntos += 3; $ev += "usa $nom para ejecutar algo guardado en una carpeta del usuario" }
        elseif ($arg -match $script:RxRutaMedia) { $puntos += 1; $ev += "usa $nom para ejecutar algo guardado en ProgramData" }
        if ($arg -match $script:RxOfuscado) { $puntos += 3; $ev += 'la orden va codificada o descarga algo de internet' }
        if ($nom -eq 'mshta.exe' -and $arg -match '(?i)(https?:|javascript:|vbscript:)') { $puntos += 4; $ev += 'mshta recibe código o una dirección de internet' }
        foreach ($m in [regex]::Matches($arg, '(?i)([a-z]:\\[^"<>|*?]+?\.(cmd|bat|ps1|vbs|vbe|js|jse|hta|wsf|csproj|proj|exe|dll))')) {
            $ruta = $m.Groups[1].Value; $ok = $false
            try { $ok = Test-Path -LiteralPath $ruta -PathType Leaf } catch {}
            if (-not $ok) { $ev += "el archivo al que apunta ya no existe ($ruta)"; break }
        }
    }
    elseif (($exe -match $script:RxRutaAlta) -or ($exe -match $script:RxCacheWin)) {
        $ok = $false; try { $ok = Test-Path -LiteralPath $exe -PathType Leaf } catch {}
        if ($ok) {
            $firma = 'NotSigned'; try { $firma = [string](Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop).Status } catch {}
            if ($firma -ne 'Valid') { $puntos += 3; $ev += 'ejecuta un programa sin firma digital guardado en una carpeta del usuario' }
            if ($exe -match $script:RxCacheWin) { $puntos += 3; $ev += 'el programa está en una carpeta de caché de Windows' }
        }
        else { $puntos += 1; $ev += 'apunta a un programa en carpeta del usuario que ya no existe' }
    }
    return [pscustomobject]@{ Puntos = $puntos; Evidencia = $ev; Exe = $exe; Nombre = $nom }
}

function Nuevo-Hallazgo([hashtable]$H) {
    return [pscustomobject]@{
        Nivel     = [string]$H.Nivel
        Tipo      = [string]$H.Tipo
        Titulo    = [string]$H.Titulo
        Donde     = [string]$H.Donde
        Evidencia = @($H.Evidencia | Where-Object { $_ })
        QueHacer  = [string]$H.QueHacer
        Archivos  = @($H.Archivos | Where-Object { $_ })
        Carpeta   = [string]$H.Carpeta
        Tarea     = [string]$H.Tarea
    }
}

function Nuevo-Veredicto([string]$Nivel, [bool]$Matar, [string]$Raiz, [string]$Motivo) {
    return [pscustomobject]@{ Nivel = $Nivel; Matar = $Matar; Raiz = $Raiz; Motivo = $Motivo }
}

# ---------------------------------------------------------------------------------------------
#  Revisión: tareas programadas
# ---------------------------------------------------------------------------------------------
function Obtener-Tareas {
    $res = New-Object System.Collections.Generic.List[object]
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $pend = New-Object System.Collections.Stack
        $pend.Push($svc.GetFolder('\'))
        while ($pend.Count -gt 0) {
            $f = $pend.Pop()
            try { foreach ($s in $f.GetFolders(0)) { $pend.Push($s) } } catch {}
            try {
                foreach ($t in $f.GetTasks(1)) {
                    try {
                        $def = $t.Definition; $acc = @()
                        foreach ($a in $def.Actions) { if ($a.Type -eq 0) { $acc += [pscustomobject]@{ Exe = [string]$a.Path; Argumentos = [string]$a.Arguments } } }
                        $ini = $false
                        foreach ($tr in $def.Triggers) { if ($tr.Type -eq 8 -or $tr.Type -eq 9) { $ini = $true } }
                        $res.Add([pscustomobject]@{ Nombre = [string]$t.Name; Ruta = [string]$f.Path; Completa = [string]$t.Path; Autor = [string]$def.RegistrationInfo.Author; Oculta = [bool]$def.Settings.Hidden; Activa = [bool]$t.Enabled; Acciones = $acc; AlIniciar = $ini })
                    } catch {}
                }
            } catch {}
        }
    } catch {}
    return $res
}

function Evaluar-Tarea($T) {
    $puntos = 0; $ev = @()
    foreach ($a in @($T.Acciones)) {
        $r = Evaluar-Comando $a.Exe $a.Argumentos
        $puntos += $r.Puntos; $ev += $r.Evidencia
    }
    $base = ([string]$T.Nombre).ToLower() -replace '\.exe$', ''
    if ($T.Ruta -eq '\' -and $script:NombresSistema -contains $base) { $puntos += 3; $ev += "se llama igual que un programa de Windows ($($T.Nombre)) para pasar desapercibida" }
    if ($puntos -gt 0) {
        if ($T.Oculta) { $puntos += 1; $ev += 'está marcada como oculta' }
        if (-not $T.Autor -and $T.Ruta -eq '\') { $ev += 'no dice quién la creó' }
        if ($T.AlIniciar) { $ev += 'se ejecuta sola al iniciar sesión o al encender' }
    }
    $nivel = $null
    if ($puntos -ge 4) { $nivel = 'ALTO' } elseif ($puntos -ge 2) { $nivel = 'MEDIO' }
    if (-not $nivel) { return $null }
    $ordenes = (@($T.Acciones) | ForEach-Object { ("{0} {1}" -f $_.Exe, $_.Argumentos).Trim() }) -join '  |  '
    $estado = 'activa'; if (-not $T.Activa) { $estado = 'desactivada (no corre, pero sigue ahí)' }
    return (Nuevo-Hallazgo @{
            Nivel = $nivel; Tipo = 'tarea'; Titulo = "Tarea programada sospechosa: $($T.Nombre)"
            Donde = "Programador de tareas: $($T.Completa)"
            Evidencia = @("orden: $ordenes", "estado: $estado") + $ev
            Tarea = $T.Completa
            QueHacer = 'Abre Velador como administrador (clic derecho en Velador.cmd) y elige Limpiar para borrarla.'
        })
}

function Revisar-Tareas {
    if ($script:Aislado) { return }
    foreach ($t in @(Obtener-Tareas)) { $h = Evaluar-Tarea $t; if ($h) { $h } }
}

# ---------------------------------------------------------------------------------------------
#  Revisión: programas que arrancan con Windows
# ---------------------------------------------------------------------------------------------
function Revisar-Inicio {
    if ($script:Aislado) { return }
    $propias = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
    $claves = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
    foreach ($k in $claves) {
        $p = $null; try { $p = Get-ItemProperty -Path $k -ErrorAction Stop } catch { continue }
        foreach ($prop in $p.PSObject.Properties) {
            if ($propias -contains $prop.Name) { continue }
            $linea = [string]$prop.Value
            $sc = Separar-Comando $linea
            $r = Evaluar-Comando $sc[0] $sc[1]
            if ($r.Puntos -lt 2) { continue }
            $nivel = 'MEDIO'; if ($r.Puntos -ge 4) { $nivel = 'ALTO' }
            Nuevo-Hallazgo @{ Nivel = $nivel; Tipo = 'inicio'; Titulo = "Arranca con Windows: $($prop.Name)"; Donde = "Registro: $k"; Evidencia = @("orden: $linea") + $r.Evidencia; QueHacer = 'Si no reconoces este programa, quítalo en Administrador de tareas > Aplicaciones de arranque.' }
        }
    }
    $sh = $null; try { $sh = New-Object -ComObject WScript.Shell } catch {}
    foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Force -File -ErrorAction SilentlyContinue)) {
            $e = $f.Extension.ToLower()
            if ($f.Name -eq 'desktop.ini') { continue }
            $exe = $f.FullName; $argu = ''
            if ($e -eq '.lnk' -and $sh) {
                try { $l = $sh.CreateShortcut($f.FullName); $exe = [string]$l.TargetPath; $argu = [string]$l.Arguments } catch {}
                if ($f.Name -eq 'Velador.lnk' -and $argu -match 'velador\.ps1') { continue }
                $r = Evaluar-Comando $exe $argu
                if ($r.Puntos -lt 2) { continue }
                $nivel = 'MEDIO'; if ($r.Puntos -ge 4) { $nivel = 'ALTO' }
                Nuevo-Hallazgo @{ Nivel = $nivel; Tipo = 'inicio'; Titulo = "Arranca con Windows: $($f.BaseName)"; Donde = $f.FullName; Evidencia = @("orden: $exe $argu") + $r.Evidencia; QueHacer = 'Si no reconoces este acceso directo, bórralo de la carpeta Inicio.' }
            }
            elseif (@('.cmd', '.bat', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta') -contains $e) {
                Nuevo-Hallazgo @{ Nivel = 'MEDIO'; Tipo = 'inicio'; Titulo = "Un archivo de órdenes arranca con Windows: $($f.Name)"; Donde = $f.FullName; Evidencia = @('los programas normales no ponen archivos de órdenes sueltos en la carpeta Inicio'); QueHacer = 'Si no lo pusiste tú, bórralo de la carpeta Inicio.' }
            }
        }
    }
}

# ---------------------------------------------------------------------------------------------
#  Revisión: carpetas con restos (cachés de Windows y proyectos cargadores)
# ---------------------------------------------------------------------------------------------
function Revisar-Carpetas {
    $porDir = @{}
    $nota = {
        param($dir, $archivo, $texto, $fuerte, $cache)
        $k = $dir.ToLower()
        if (-not $porDir.ContainsKey($k)) {
            $porDir[$k] = @{ Dir = $dir; Archivos = (New-Object System.Collections.Generic.List[string]); Ev = (New-Object System.Collections.Generic.List[string]); Fuerte = $false; Cache = $false }
        }
        $r = $porDir[$k]
        if ($archivo -and -not $r.Archivos.Contains($archivo)) { $r.Archivos.Add($archivo) }
        if ($texto -and -not $r.Ev.Contains($texto)) { $r.Ev.Add($texto) }
        if ($fuerte) { $r.Fuerte = $true }
        if ($cache) { $r.Cache = $true }
    }

    # 1) Carpetas donde Windows solo guarda datos: ahí no debe haber nada ejecutable
    $raizWin = $script:RaizCache
    if (-not $raizWin -and -not $script:Aislado) { $raizWin = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows' }
    $raizWin = Ruta-Larga $raizWin
    $perfil = $null; try { $perfil = (Get-Item -LiteralPath $env:USERPROFILE -Force).CreationTime } catch {}
    if ($raizWin) {
        foreach ($n in @('Caches', 'WebCache', 'INetCache', 'History', 'INetCookies')) {
            $d = Join-Path $raizWin $n
            if (-not (Test-Path -LiteralPath $d)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $d -Force -File -ErrorAction SilentlyContinue)) {
                $e = $f.Extension.ToLower()
                if ($script:ExtEjecutable -notcontains $e) { continue }
                & $nota $d $f.FullName 'hay archivos ejecutables en una carpeta donde Windows solo guarda datos' $false $true
                if (($f.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) { & $nota $d $null 'los archivos están ocultos' $false $true }
                if ($perfil -and $f.CreationTime -lt $perfil.AddDays(-1)) { & $nota $d $null ('tienen fecha de creación falsa ({0:yyyy-MM-dd}): es anterior a que existiera tu usuario en esta computadora' -f $f.CreationTime) $false $true }
                if ($script:ExtProyecto -contains $e) { foreach ($i in @(Buscar-IndicadoresProyecto $f.FullName)) { & $nota $d $null $i.Texto $i.Fuerte $true } }
            }
        }
    }

    # 2) Proyectos de MSBuild que cargan programas escondidos, en cualquier carpeta del usuario
    $raices = @()
    if (-not $script:Aislado) { $raices += @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP, (Join-Path $env:USERPROFILE 'Downloads'), $env:PUBLIC, $env:ProgramData) }
    $raices += @($script:CarpetasExtra)
    if ($script:RaizCache) { $raices += $script:RaizCache }
    foreach ($f in @(Listar-Archivos $raices $script:ExtProyecto 12)) {
        $ind = @(Buscar-IndicadoresProyecto $f)
        if ($ind.Count -eq 0) { continue }
        $d = Split-Path -Parent $f
        foreach ($i in $ind) { & $nota $d $f $i.Texto $i.Fuerte $false }
    }

    # 3) Acompañantes: el resto del proyecto y el archivo de órdenes que lo lanza
    foreach ($k in @($porDir.Keys)) {
        $r = $porDir[$k]
        if (-not $r.Fuerte) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $r.Dir -Force -File -ErrorAction SilentlyContinue)) {
            $e = $f.Extension.ToLower()
            if ($script:ExtProyecto -contains $e) {
                if (-not $r.Archivos.Contains($f.FullName)) { $r.Archivos.Add($f.FullName) }
            }
            elseif (@('.cmd', '.bat') -contains $e -and $f.Length -lt 200KB) {
                $c = ''; try { $c = [IO.File]::ReadAllText($f.FullName) } catch {}
                if ($c -match '(?i)msbuild') {
                    if (-not $r.Archivos.Contains($f.FullName)) { $r.Archivos.Add($f.FullName) }
                    & $nota $r.Dir $null ("un archivo de órdenes ({0}) lanza MSBuild sin mostrar ventana" -f $f.Name) $true $false
                }
            }
        }
    }

    foreach ($r in $porDir.Values) {
        $nivel = 'MEDIO'; $titulo = 'Archivos de proyecto con contenido raro'
        $que = 'Si no reconoces esta carpeta, mándala a revisar. No abras esos archivos.'
        if ($r.Fuerte) { $nivel = 'ALTO'; $titulo = 'Cargador escondido: MSBuild arma y ejecuta un programa oculto'; $que = 'Mándalo a cuarentena con la opción Limpiar. Después cambia tus contraseñas desde otro dispositivo.' }
        elseif ($r.Cache) { $nivel = 'ALTO'; $titulo = 'Archivos ejecutables en una carpeta de caché de Windows'; $que = 'Mándalos a cuarentena con la opción Limpiar.' }
        Nuevo-Hallazgo @{ Nivel = $nivel; Tipo = 'archivos'; Titulo = $titulo; Donde = $r.Dir; Evidencia = @($r.Ev); Archivos = @($r.Archivos); QueHacer = $que }
    }

    # 4) Carpetas temporales que deja el instalador falso al desempacarse
    if (-not $script:Aislado) {
        foreach ($base in @($env:TEMP, (Join-Path $env:USERPROFILE 'Downloads'))) {
            if (-not $base -or -not (Test-Path -LiteralPath $base)) { continue }
            $base = Ruta-Larga $base
            foreach ($d in @(Get-ChildItem -LiteralPath $base -Directory -Force -Filter 'tmp-*' -ErrorAction SilentlyContinue)) {
                if ($d.Name -notmatch '^tmp-\d{5}-[A-Za-z0-9]{12}$') { continue }
                Nuevo-Hallazgo @{ Nivel = 'ALTO'; Tipo = 'carpeta'; Titulo = 'Carpeta temporal de un instalador falso'; Donde = $d.FullName; Evidencia = @('el nombre sigue el patrón que usa este tipo de cargador al desempacarse'); Carpeta = $d.FullName; QueHacer = 'Mándala a cuarentena con la opción Limpiar.' }
            }
        }
    }
}

# ---------------------------------------------------------------------------------------------
#  Revisión: instaladores falsos (motor de juegos Ren'Py usado de disfraz)
# ---------------------------------------------------------------------------------------------
function Probar-InstaladorFalso([string]$Dir) {
    if (-not $Dir) { return $null }
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $Dir 'renpy'))) { return $null }
        if (-not (Test-Path -LiteralPath (Join-Path $Dir 'lib'))) { return $null }
    } catch { return $null }
    $ev = @(); $fuerte = $false
    foreach ($jd in @('data', 'game')) {
        $g = Join-Path $Dir $jd
        if (-not (Test-Path -LiteralPath $g)) { continue }
        $pp = Join-Path $g 'python-packages'
        if (Test-Path -LiteralPath $pp) {
            foreach ($py in @(Get-ChildItem -LiteralPath $pp -Recurse -Filter '*.py' -File -Force -ErrorAction SilentlyContinue | Select-Object -First 60)) {
                if ($py.Length -gt 2MB) { continue }
                $c = ''; try { $c = [IO.File]::ReadAllText($py.FullName) } catch {}
                if ($c -match '(?i)VBoxGuest|is_sandboxed|vmtoolsd|check_vm_|wdagutilityaccount') { $ev += "trae código para detectar las máquinas de prueba de los analistas de virus ($($py.Name))"; $fuerte = $true; break }
            }
            $pad = Get-ChildItem -LiteralPath $pp -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB } | Select-Object -First 1
            if ($pad) { $ev += ("trae un archivo de relleno de {0:N0} MB para que el antivirus no lo examine ({1})" -f ($pad.Length / 1MB), $pad.Name) }
        }
        $dot = Get-ChildItem -LiteralPath $g -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name.StartsWith('.') -and $_.Length -ge 100 -and $_.Length -le 4096 } | Select-Object -First 1
        if ($dot) {
            $txt = ''; try { $txt = [IO.File]::ReadAllText($dot.FullName).Trim() } catch {}
            if ($txt -match '^[A-Za-z0-9+/=\r\n]+$') {
                $normales = @('.rpa', '.rpyc', '.rpy', '.rpyb', '.rpymc', '.png', '.jpg', '.jpeg', '.webp', '.ogg', '.mp3', '.wav', '.webm', '.ttf', '.otf', '.txt', '.json')
                $grande = Get-ChildItem -LiteralPath $g -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 1MB -and ($normales -notcontains $_.Extension.ToLower()) } | Select-Object -First 1
                if ($grande) { $ev += ("trae una configuración oculta ({0}) junto a una carga cifrada ({1}, {2:N1} MB)" -f $dot.Name, $grande.Name, ($grande.Length / 1MB)); $fuerte = $true }
                try {
                    $clave = [Text.Encoding]::ASCII.GetBytes('81034149cd6f48c8821340204f92766e')
                    $b = [Convert]::FromBase64String($txt)
                    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor $clave[$i % $clave.Length] }
                    $j = [Text.Encoding]::UTF8.GetString($b)
                    if ($j -match '"exc_fl"\s*:\s*"([^"]+)"') { $ev += "su configuración descifrada dice que va a ejecutar a escondidas '$($Matches[1])'"; $fuerte = $true }
                } catch {}
            }
        }
    }
    if ($ev.Count -eq 0) { return $null }
    return [pscustomobject]@{ Dir = $Dir; Fuerte = $fuerte; Evidencia = @('usa el motor de juegos Ren''Py como disfraz de instalador') + $ev }
}

function Revisar-InstaladoresFalsos {
    $raices = @()
    if (-not $script:Aislado) { $raices += @((Join-Path $env:USERPROFILE 'Downloads'), [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('MyDocuments'), $env:TEMP) }
    $raices += @($script:CarpetasExtra)
    $vistos = @{}
    foreach ($r in @($raices | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | ForEach-Object { Ruta-Larga $_ } | Select-Object -Unique)) {
        $cands = @()
        if (Test-Path -LiteralPath (Join-Path $r 'renpy')) { $cands += $r }
        try { $cands += @(Get-ChildItem -LiteralPath $r -Directory -Recurse -Depth 3 -Filter 'renpy' -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Parent.FullName }) } catch {}
        foreach ($d in $cands) {
            if ($vistos.ContainsKey($d.ToLower())) { continue }
            $vistos[$d.ToLower()] = 1
            $f = Probar-InstaladorFalso $d
            if (-not $f) { continue }
            $nivel = 'MEDIO'; if ($f.Fuerte) { $nivel = 'ALTO' }
            Nuevo-Hallazgo @{ Nivel = $nivel; Tipo = 'carpeta'; Titulo = 'Instalador falso: un cargador disfrazado de programa'; Donde = $d; Evidencia = $f.Evidencia; Carpeta = $d; QueHacer = 'No lo abras. Mándalo a cuarentena con la opción Limpiar. Si ya lo abriste, cambia tus contraseñas desde otro dispositivo.' }
        }
    }
}

# ---------------------------------------------------------------------------------------------
#  Regla de procesos (la usan la revisión y el vigilante)
# ---------------------------------------------------------------------------------------------
function Clasificar-Proceso([string]$Nombre, [string]$Ruta, [string]$Cl, [string]$NombrePadre, [string]$ClPadre) {
    $nom = $Nombre.ToLower(); $padre = $NombrePadre.ToLower()
    if ($Ruta -and $Ruta -match $script:RxCacheWin) {
        return (Nuevo-Veredicto 'ALTO' $true 'propio' "se ejecutó un programa desde una carpeta de caché de Windows ($Ruta)")
    }
    $rutas = @(Extraer-Rutas $Cl | Where-Object { $n = ''; try { $n = [IO.Path]::GetFileName($_).ToLower() } catch {}; $n -ne $nom })

    if ($nom -eq 'msbuild.exe') {
        $s = $rutas | Where-Object { ($_ -match $script:RxRutaAlta) -or ($_ -match $script:RxCacheWin) } | Select-Object -First 1
        if (-not $s -and $padre -eq 'cmd.exe' -and $ClPadre) {
            $s = @(Extraer-Rutas $ClPadre) | Where-Object { $_ -match '(?i)\.(cmd|bat)$' -and (($_ -match $script:RxRutaAlta) -or ($_ -match $script:RxCacheWin)) } | Select-Object -First 1
        }
        if ($s) { return (Nuevo-Veredicto 'ALTO' $true 'propio' "MSBuild se lanzó sobre archivos guardados en una carpeta del usuario ($s). Así se arma y se ejecuta un programa oculto en la memoria") }
        return $null
    }
    if ($script:HostsNet -contains $nom) {
        if ($Cl) {
            $resto = ($Cl.Trim() -replace '^("[^"]*"|\S+)\s*', '')
            if (-not $resto) { return (Nuevo-Veredicto 'ALTO' $true 'propio' "$Nombre se abrió sin ninguna instrucción: es la forma típica de esconder otro programa adentro") }
            $s = $rutas | Where-Object { $_ -match $script:RxRutaAlta } | Select-Object -First 1
            if ($s) { return (Nuevo-Veredicto 'MEDIO' $false 'propio' "$Nombre está trabajando con un archivo guardado en una carpeta del usuario ($s)") }
        }
        return $null
    }
    if ($padre -eq 'conhost.exe' -and ($script:Interpretes -contains $nom) -and ($ClPadre -match '(?i)--headless') -and ($ClPadre -notmatch '(?i)--(server|signal)\b')) {
        if (($Cl -match $script:RxRutaAlta) -or ($Cl -match $script:RxCacheWin) -or ($ClPadre -match $script:RxRutaAlta) -or ($ClPadre -match $script:RxCacheWin)) {
            return (Nuevo-Veredicto 'ALTO' $true 'padre' "se abrió una orden invisible (conhost --headless) que ejecuta un archivo guardado en una carpeta del usuario: $Cl")
        }
        return (Nuevo-Veredicto 'MEDIO' $false 'padre' "un programa abrió una orden invisible con conhost --headless: $Cl")
    }
    if ($nom -eq 'forfiles.exe' -and $Cl -match '(?i)/c\s+"?\s*cmd(\.exe)?\s+/c\s+(call\s+@|@path|start\s+[^"]*@(path|file)|ren\s+@file)') {
        $dir = ''
        if ($Cl -match '(?i)/p\s+"([^"]+)"') { $dir = $Matches[1] } elseif ($Cl -match '(?i)/p\s+(\S+)') { $dir = $Matches[1] }
        if ((("$dir\") -match $script:RxRutaAlta) -or (("$dir\") -match $script:RxCacheWin)) {
            return (Nuevo-Veredicto 'ALTO' $true 'propio' "forfiles se usó para ejecutar a escondidas un archivo de $dir")
        }
        return $null
    }
    if (@('wscript.exe', 'cscript.exe', 'mshta.exe') -contains $nom) {
        if ($nom -eq 'mshta.exe' -and $Cl -match '(?i)(https?:|javascript:|vbscript:)') {
            return (Nuevo-Veredicto 'ALTO' $true 'propio' 'mshta se abrió con código o con una dirección de internet')
        }
        $s = $rutas | Where-Object { ($_ -match '(?i)\.(js|jse|vbs|vbe|wsf|wsh|hta|sct)$') -and (($_ -match '(?i)\\(Temp|Downloads|Descargas)\\') -or ($_ -match $script:RxCacheWin)) } | Select-Object -First 1
        if ($s) { return (Nuevo-Veredicto 'ALTO' $true 'propio' "se abrió un archivo de órdenes descargado ($s)") }
        return $null
    }
    if ($nom -eq 'schtasks.exe' -and $Cl -match '(?i)/create') {
        $tr = ''
        if ($Cl -match '(?i)/tr\s+"((?:[^"\\]|\\.)*)"') { $tr = ($Matches[1] -replace '\\"', '"') } elseif ($Cl -match '(?i)/tr\s+(\S+)') { $tr = $Matches[1] }
        if ($tr) {
            $sc = Separar-Comando $tr
            $r = Evaluar-Comando $sc[0] $sc[1]
            if ($r.Puntos -ge 3) { return (Nuevo-Veredicto 'ALTO' $false 'propio' ('se está creando una tarea programada sospechosa: ' + ($r.Evidencia -join '; '))) }
        }
    }
    return $null
}

function Revisar-Procesos {
    if ($script:Aislado) { return }
    $todos = @(); try { $todos = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine -ErrorAction Stop) } catch { return }
    $porId = @{}; foreach ($p in $todos) { $porId[[uint32]$p.ProcessId] = $p }
    foreach ($p in $todos) {
        if ([uint32]$p.ProcessId -eq $PID) { continue }
        $pa = $porId[[uint32]$p.ParentProcessId]; $np = ''; $cp = ''
        if ($pa) { $np = [string]$pa.Name; $cp = [string]$pa.CommandLine }
        $v = Clasificar-Proceso ([string]$p.Name) ([string]$p.ExecutablePath) ([string]$p.CommandLine) $np $cp
        if (-not $v) { continue }
        Nuevo-Hallazgo @{ Nivel = $v.Nivel; Tipo = 'proceso'; Titulo = "Programa sospechoso en marcha: $($p.Name)"; Donde = "proceso número $($p.ProcessId)"; Evidencia = @($v.Motivo, ("orden: " + [string]$p.CommandLine)); QueHacer = 'Enciende el vigilante: detiene esto en cuanto aparece. Después usa Limpiar.' }
    }
}

# ---------------------------------------------------------------------------------------------
#  Revisión: cómo está la protección de Windows
# ---------------------------------------------------------------------------------------------
function Revisar-Proteccion {
    if ($script:Aislado) { return }
    $st = $null; try { $st = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if (-not $st) {
        Nuevo-Hallazgo @{ Nivel = 'INFO'; Tipo = 'config'; Titulo = 'No se pudo leer el estado del antivirus de Windows'; Evidencia = @('puede que uses otro antivirus'); QueHacer = 'Revisa que tu antivirus esté encendido y al día.' }
    }
    else {
        if (-not $st.RealTimeProtectionEnabled) {
            Nuevo-Hallazgo @{ Nivel = 'ALTO'; Tipo = 'config'; Titulo = 'El antivirus está apagado en este momento'; Evidencia = @('la protección en tiempo real de Microsoft Defender no está activa'); QueHacer = 'Enciéndelo: Seguridad de Windows > Protección contra virus y amenazas > Administrar la configuración.' }
        }
        if ($st.PSObject.Properties['IsTamperProtected'] -and -not $st.IsTamperProtected) {
            Nuevo-Hallazgo @{ Nivel = 'MEDIO'; Tipo = 'config'; Titulo = 'La protección contra alteraciones está apagada'; Evidencia = @('sin ella, un programa puede apagar el antivirus sin que te enteres'); QueHacer = 'Actívala en Seguridad de Windows > Protección contra virus y amenazas > Administrar la configuración.' }
        }
        if ([int64]$st.AntivirusSignatureAge -gt 7 -and [int64]$st.AntivirusSignatureAge -lt 100000) {
            Nuevo-Hallazgo @{ Nivel = 'MEDIO'; Tipo = 'config'; Titulo = "El antivirus lleva $($st.AntivirusSignatureAge) días sin actualizarse"; Evidencia = @('las definiciones de virus están viejas'); QueHacer = 'Abre Windows Update y busca actualizaciones.' }
        }
        if (-not $st.FullScanEndTime) {
            Nuevo-Hallazgo @{ Nivel = 'INFO'; Tipo = 'config'; Titulo = 'Nunca se ha hecho un examen completo del antivirus'; Evidencia = @('solo se han hecho exámenes rápidos, que no revisan todo el disco'); QueHacer = 'Seguridad de Windows > Protección contra virus y amenazas > Opciones de examen > Examen completo.' }
        }
    }
    $apagados = @()
    try { $apagados = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001; StartTime = (Get-Date).AddDays(-180) } -ErrorAction Stop) } catch {}
    if ($apagados.Count -gt 0) {
        $fechas = @($apagados | Sort-Object TimeCreated -Descending | Select-Object -First 8 | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') })
        $veces = 'veces'; if ($apagados.Count -eq 1) { $veces = 'vez' }
        Nuevo-Hallazgo @{ Nivel = 'MEDIO'; Tipo = 'config'; Titulo = "El antivirus se apagó $($apagados.Count) $veces en los últimos 6 meses"; Evidencia = @('fechas: ' + ($fechas -join ', ')); QueHacer = 'Si un instalador te pidió apagarlo: ningún programa legítimo lo pide. Lo que se haya abierto en esos minutos no fue revisado.' }
    }
    $pref = $null; try { $pref = Get-MpPreference -ErrorAction Stop } catch {}
    $reglas = 0; try { $reglas = @(Get-NetFirewallRule -Group 'Velador' -ErrorAction Stop).Count } catch {}
    if ($reglas -eq 0) {
        $extra = @('los programas de Windows que el malware usa de disfraz todavía pueden conectarse a internet')
        if ($pref -and [int]$pref.PUAProtection -ne 1) { $extra += 'el bloqueo de programas no deseados del antivirus no está activo' }
        Nuevo-Hallazgo @{ Nivel = 'INFO'; Tipo = 'config'; Titulo = 'El blindaje de Velador no está aplicado'; Evidencia = $extra; QueHacer = 'En el menú de Velador elige Blindar.' }
    }
    $uac = $null; try { $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA } catch {}
    if ($null -ne $uac -and [int]$uac -eq 0) {
        Nuevo-Hallazgo @{ Nivel = 'ALTO'; Tipo = 'config'; Titulo = 'El Control de cuentas de usuario (UAC) está apagado'; Evidencia = @('cualquier programa puede hacer cambios de administrador sin preguntarte'); QueHacer = 'Panel de control > Cuentas de usuario > Cambiar configuración de Control de cuentas de usuario.' }
    }
}

# ---------------------------------------------------------------------------------------------
#  Revisión completa e informe
# ---------------------------------------------------------------------------------------------
function Ejecutar-Revision([switch]$Silencioso) {
    $h = New-Object System.Collections.Generic.List[object]
    [void](Cargar-Nativo)
    $pasos = @(
        @{ N = 'Tareas programadas'; F = { Revisar-Tareas } },
        @{ N = 'Programas que arrancan con Windows'; F = { Revisar-Inicio } },
        @{ N = 'Carpetas con restos'; F = { Revisar-Carpetas } },
        @{ N = 'Instaladores falsos'; F = { Revisar-InstaladoresFalsos } },
        @{ N = 'Programas en marcha'; F = { Revisar-Procesos } },
        @{ N = 'Protección de Windows'; F = { Revisar-Proteccion } }
    )
    foreach ($p in $pasos) {
        if (-not $Silencioso) { Write-Host ("  - {0}..." -f $p.N) }
        try { foreach ($x in @(& $p.F)) { if ($x) { $h.Add($x) } } }
        catch { Escribir-Registro 'ERROR' ("{0}: {1}" -f $p.N, $_.Exception.Message) }
    }
    $orden = @{ ALTO = 0; MEDIO = 1; INFO = 2 }
    return @($h | Sort-Object { $orden[$_.Nivel] })
}

function Mostrar-Hallazgos($H) {
    $lista = @($H)
    $alto = @($lista | Where-Object { $_.Nivel -eq 'ALTO' }).Count
    $medio = @($lista | Where-Object { $_.Nivel -eq 'MEDIO' }).Count
    Write-Host ''
    if ($alto -gt 0) { Write-Host ("  RESULTADO: {0} hallazgo(s) graves y {1} por revisar" -f $alto, $medio) -ForegroundColor Red }
    elseif ($medio -gt 0) { Write-Host ("  RESULTADO: nada grave; {0} cosa(s) por revisar" -f $medio) -ForegroundColor Yellow }
    else { Write-Host '  RESULTADO: no se encontró nada sospechoso' -ForegroundColor Green }
    foreach ($x in $lista) {
        $color = 'Cyan'; if ($x.Nivel -eq 'ALTO') { $color = 'Red' } elseif ($x.Nivel -eq 'MEDIO') { $color = 'Yellow' }
        Write-Host ''
        Write-Host ("  [{0}] {1}" -f $x.Nivel, $x.Titulo) -ForegroundColor $color
        if ($x.Donde) { Write-Host ("        Dónde: {0}" -f $x.Donde) }
        foreach ($e in @($x.Evidencia)) { Write-Host ("        - {0}" -f $e) }
        foreach ($a in @($x.Archivos)) { Write-Host ("        archivo: {0}" -f (Split-Path -Leaf $a)) }
        if ($x.QueHacer) { Write-Host ("        Qué hacer: {0}" -f $x.QueHacer) -ForegroundColor Gray }
    }
    Write-Host ''
}

function Escribir-InformeHtml($H, [string]$Ruta) {
    $lista = @($H)
    $alto = @($lista | Where-Object { $_.Nivel -eq 'ALTO' }).Count
    $medio = @($lista | Where-Object { $_.Nivel -eq 'MEDIO' }).Count
    $estado = 'No se encontró nada sospechoso'; $clase = 'ok'
    if ($alto -gt 0) { $estado = "$alto hallazgo(s) graves"; $clase = 'alto' } elseif ($medio -gt 0) { $estado = "Nada grave; $medio cosa(s) por revisar"; $clase = 'medio' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@'
<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de Velador</title>
<style>
:root{--fondo:#f4f5f7;--tarjeta:#fff;--texto:#1c2330;--suave:#5b6577;--borde:#dde1e8;--alto:#c62828;--medio:#a85f00;--info:#1565c0;--ok:#2e7d32}
@media (prefers-color-scheme:dark){:root{--fondo:#12151b;--tarjeta:#1b2029;--texto:#e7ebf2;--suave:#9aa5b8;--borde:#2c3442;--alto:#f07a7a;--medio:#e0a44a;--info:#6aa9ee;--ok:#74c57b}}
*{box-sizing:border-box}body{margin:0;background:var(--fondo);color:var(--texto);font:16px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:28px 16px 48px}
h1{font-size:26px;margin:0 0 4px}.sub{color:var(--suave);margin:0 0 20px}
.estado{border-radius:12px;padding:16px 18px;font-size:19px;font-weight:600;color:#fff;margin-bottom:22px}
.estado.alto{background:var(--alto)}.estado.medio{background:var(--medio)}.estado.ok{background:var(--ok)}
.h{background:var(--tarjeta);border:1px solid var(--borde);border-left:6px solid var(--info);border-radius:10px;padding:14px 16px;margin:0 0 14px}
.h.ALTO{border-left-color:var(--alto)}.h.MEDIO{border-left-color:var(--medio)}
.h h2{font-size:17px;margin:0 0 6px}.niv{font-size:12px;font-weight:700;letter-spacing:.04em;margin-right:8px}
.ALTO .niv{color:var(--alto)}.MEDIO .niv{color:var(--medio)}.INFO .niv{color:var(--info)}
.donde{color:var(--suave);font-size:14px;word-break:break-all;margin:0 0 6px}
ul{margin:6px 0 8px;padding-left:20px}li{word-break:break-word}
.que{background:var(--fondo);border-radius:8px;padding:8px 10px;font-size:15px}
.arch{font:13px/1.4 Consolas,monospace;color:var(--suave);word-break:break-all}
footer{color:var(--suave);font-size:13px;margin-top:26px}
</style></head><body><main>
<h1>Informe de Velador</h1>
'@)
    $c = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    [void]$sb.AppendLine(('<p class="sub">{0} &middot; {1}</p>' -f (& $c $env:COMPUTERNAME), (Get-Date -Format 'yyyy-MM-dd HH:mm')))
    [void]$sb.AppendLine(('<div class="estado {0}">{1}</div>' -f $clase, (& $c $estado)))
    foreach ($x in $lista) {
        [void]$sb.AppendLine(('<section class="h {0}"><h2><span class="niv">{0}</span>{1}</h2>' -f $x.Nivel, (& $c $x.Titulo)))
        if ($x.Donde) { [void]$sb.AppendLine(('<p class="donde">{0}</p>' -f (& $c $x.Donde))) }
        if (@($x.Evidencia).Count -gt 0) {
            [void]$sb.AppendLine('<ul>')
            foreach ($e in @($x.Evidencia)) { [void]$sb.AppendLine(('<li>{0}</li>' -f (& $c $e))) }
            [void]$sb.AppendLine('</ul>')
        }
        foreach ($a in @($x.Archivos)) { [void]$sb.AppendLine(('<div class="arch">{0}</div>' -f (& $c $a))) }
        if ($x.QueHacer) { [void]$sb.AppendLine(('<p class="que"><strong>Qué hacer:</strong> {0}</p>' -f (& $c $x.QueHacer))) }
        [void]$sb.AppendLine('</section>')
    }
    [void]$sb.AppendLine(('<footer>Velador {0}. Esta revisión no cambió nada en la computadora. Velador no sustituye a un antivirus.</footer></main></body></html>' -f $script:Version))
    [IO.File]::WriteAllText($Ruta, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Hacer-Revision {
    Write-Host ''
    Write-Host '  Revisando la computadora (puede tardar un par de minutos)...' -ForegroundColor Cyan
    $t0 = Get-Date
    $h = @(Ejecutar-Revision)
    Mostrar-Hallazgos $h
    $html = Join-Path $script:Datos ('informe-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.html')
    try { Escribir-InformeHtml $h $html } catch { Escribir-Registro 'ERROR' ('informe: ' + $_.Exception.Message) }
    try { [IO.File]::WriteAllText((Join-Path $script:Datos 'ultimo-informe.json'), (A-Json $h 6), (New-Object System.Text.UTF8Encoding($false))) } catch {}
    Escribir-Registro 'INFO' ("Revisión terminada: {0} graves, {1} por revisar, {2:N0} s" -f @($h | Where-Object { $_.Nivel -eq 'ALTO' }).Count, @($h | Where-Object { $_.Nivel -eq 'MEDIO' }).Count, ((Get-Date) - $t0).TotalSeconds)
    Write-Host ("  Informe guardado en: {0}" -f $html)
    if (-not $script:SinAbrir -and -not $script:Aislado) { try { Start-Process $html } catch {} }
    return $h
}

# ---------------------------------------------------------------------------------------------
#  Cuarentena (mover, no borrar) y restauración
# ---------------------------------------------------------------------------------------------
function Mover-ACuarentena([string]$Origen, [string]$Lote, [ref]$Indice) {
    $fi = Get-Item -LiteralPath $Origen -Force -ErrorAction Stop
    $attr = [string]$fi.Attributes; $esDir = [bool]$fi.PSIsContainer
    $creado = $fi.CreationTimeUtc.ToString('o'); $modificado = $fi.LastWriteTimeUtc.ToString('o')
    if (-not $esDir) { try { $fi.Attributes = [IO.FileAttributes]::Normal } catch {} }
    $Indice.Value = $Indice.Value + 1
    $dest = Join-Path $Lote ('{0:D3}_{1}' -f $Indice.Value, $fi.Name)
    if (-not $esDir) { $dest += '.cuarentena' }
    Move-Item -LiteralPath $Origen -Destination $dest -Force -ErrorAction Stop
    return [pscustomobject]@{ Origen = $Origen; Destino = $dest; Atributos = $attr; EsCarpeta = $esDir; Creado = $creado; Modificado = $modificado }
}

function Ejecutar-Limpieza {
    Write-Host ''
    Write-Host '  Buscando qué limpiar...' -ForegroundColor Cyan
    $h = @(Ejecutar-Revision -Silencioso)
    $obj = @($h | Where-Object { $_.Nivel -eq 'ALTO' -and ((@($_.Archivos).Count -gt 0) -or $_.Carpeta -or $_.Tarea) })
    if ($obj.Count -eq 0) { Write-Host '  No hay nada grave que limpiar.' -ForegroundColor Green; return }
    Write-Host ''
    Write-Host '  Esto se va a mandar a cuarentena (se mueve, no se borra; se puede restaurar):'
    foreach ($x in $obj) {
        Write-Host ("   * {0}" -f $x.Titulo) -ForegroundColor Yellow
        foreach ($a in @($x.Archivos)) { Write-Host ("       {0}" -f $a) }
        if ($x.Carpeta) { Write-Host ("       carpeta completa: {0}" -f $x.Carpeta) }
        if ($x.Tarea) { Write-Host ("       tarea programada: {0}" -f $x.Tarea) }
    }
    if ($script:Simular) { Write-Host ''; Write-Host '  Simulación: no se movió nada.'; return }
    if ($script:Si -and -not $script:Aislado) { Write-Host '  La opción -Si solo vale en modo de pruebas. No se movió nada.'; return }
    Write-Host ''
    $ok = $false
    if ($script:Si -and $script:Aislado) { $ok = $true }
    else { try { $r = Read-Host '  Escribe SI (en mayúsculas) para continuar'; $ok = ($r -ceq 'SI') } catch { $ok = $false } }
    if (-not $ok) { Write-Host '  No se movió nada.'; return }

    $lote = Join-Path (Join-Path $script:Datos 'cuarentena') (Get-Date -Format 'yyyyMMdd-HHmmss')
    New-Item -ItemType Directory -Force -Path $lote | Out-Null
    $man = New-Object System.Collections.Generic.List[object]; $i = 0; $pend = @()
    foreach ($x in $obj) {
        foreach ($a in @($x.Archivos)) {
            try { $man.Add((Mover-ACuarentena $a $lote ([ref]$i))); Write-Host ("   movido: {0}" -f $a) }
            catch { Write-Host ("   NO se pudo mover {0}: {1}" -f $a, $_.Exception.Message) -ForegroundColor Yellow }
        }
        if ($x.Carpeta) {
            try { $man.Add((Mover-ACuarentena $x.Carpeta $lote ([ref]$i))); Write-Host ("   movida: {0}" -f $x.Carpeta) }
            catch { Write-Host ("   NO se pudo mover {0}: {1}" -f $x.Carpeta, $_.Exception.Message) -ForegroundColor Yellow }
        }
        if ($x.Tarea) {
            if (Es-Admin) {
                $xml = Join-Path $lote ('tarea_' + (($x.Tarea -replace '[\\/:*?"<>|]', '_')) + '.xml')
                try { & schtasks.exe /query /tn $x.Tarea /xml 2>$null | Set-Content -LiteralPath $xml -Encoding Unicode } catch {}
                & schtasks.exe /delete /tn $x.Tarea /f 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { $man.Add([pscustomobject]@{ Tarea = $x.Tarea; Xml = $xml }); Write-Host ("   tarea borrada: {0}" -f $x.Tarea) }
                else { Write-Host ("   NO se pudo borrar la tarea {0}" -f $x.Tarea) -ForegroundColor Yellow }
            }
            else { $pend += $x.Tarea }
        }
    }
    try { [IO.File]::WriteAllText((Join-Path $lote 'manifiesto.json'), (A-Json $man 5), (New-Object System.Text.UTF8Encoding($false))) }
    catch { Write-Host ("   OJO: no se pudo guardar la lista de la cuarentena: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
    Escribir-Registro 'INFO' ("Cuarentena: {0} elemento(s) en {1}" -f $man.Count, $lote)
    Write-Host ''
    Write-Host ("  Listo: {0} elemento(s) en cuarentena." -f $man.Count) -ForegroundColor Green
    Write-Host ("  Guardados en: {0}" -f $lote)
    if ($pend.Count -gt 0) {
        Write-Host ''
        Write-Host '  Falta borrar estas tareas programadas, que piden permiso de administrador:' -ForegroundColor Yellow
        foreach ($t in $pend) { Write-Host ("     {0}" -f $t) }
        Write-Host '  Cierra esta ventana, haz clic derecho en Velador.cmd > Ejecutar como administrador, y vuelve a elegir Limpiar.'
    }
}

function Ejecutar-Restauracion {
    $base = Join-Path $script:Datos 'cuarentena'
    $lotes = @(); if (Test-Path -LiteralPath $base) { $lotes = @(Get-ChildItem -LiteralPath $base -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'manifiesto.json') } | Sort-Object Name -Descending) }
    if ($lotes.Count -eq 0) { Write-Host '  No hay nada en cuarentena.'; return }
    $lote = $lotes[0]
    $leido = Get-Content -LiteralPath (Join-Path $lote.FullName 'manifiesto.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $man = @($leido | ForEach-Object { $_ })
    Write-Host ''
    Write-Host ("  Última cuarentena: {0} ({1} elemento(s))" -f $lote.Name, $man.Count)
    foreach ($m in $man) { if ($m.Origen) { Write-Host ("     {0}" -f $m.Origen) } elseif ($m.Tarea) { Write-Host ("     tarea: {0}" -f $m.Tarea) } }
    if ($script:Simular) { Write-Host '  Simulación: no se restauró nada.'; return }
    if (-not (Confirmar '  ¿Regresar todo esto a su lugar? Solo hazlo si estás seguro de que era inofensivo')) { Write-Host '  No se restauró nada.'; return }
    $n = 0
    foreach ($m in $man) {
        if ($m.Origen) {
            if (Test-Path -LiteralPath $m.Origen) { Write-Host ("   ya existe, se deja en cuarentena: {0}" -f $m.Origen) -ForegroundColor Yellow; continue }
            try {
                Move-Item -LiteralPath $m.Destino -Destination $m.Origen -Force -ErrorAction Stop
                $it = Get-Item -LiteralPath $m.Origen -Force
                try { $it.CreationTimeUtc = [datetime]::Parse($m.Creado).ToUniversalTime(); $it.LastWriteTimeUtc = [datetime]::Parse($m.Modificado).ToUniversalTime() } catch {}
                if (-not $m.EsCarpeta) { try { $it.Attributes = [IO.FileAttributes]$m.Atributos } catch {} }
                $n++
            } catch { Write-Host ("   NO se pudo restaurar {0}: {1}" -f $m.Origen, $_.Exception.Message) -ForegroundColor Yellow }
        }
        elseif ($m.Tarea -and $m.Xml -and (Test-Path -LiteralPath $m.Xml)) {
            if (Es-Admin) { & schtasks.exe /create /tn $m.Tarea /xml $m.Xml /f 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { $n++ } }
            else { Write-Host ("   la tarea {0} solo se puede restaurar como administrador" -f $m.Tarea) -ForegroundColor Yellow }
        }
    }
    Rename-Item -LiteralPath (Join-Path $lote.FullName 'manifiesto.json') -NewName 'manifiesto-restaurado.json' -ErrorAction SilentlyContinue
    Escribir-Registro 'INFO' ("Restauración: {0} elemento(s) de {1}" -f $n, $lote.Name)
    Write-Host ("  Restaurados: {0}" -f $n) -ForegroundColor Green
}

# ---------------------------------------------------------------------------------------------
#  Vigilante: detiene el ataque en el momento en que arranca
# ---------------------------------------------------------------------------------------------
function Linea-Comando([uint32]$Id) {
    try { $p = Get-CimInstance Win32_Process -Filter "ProcessId=$Id" -Property CommandLine -ErrorAction Stop; return [string]$p.CommandLine } catch { return '' }
}

function Detener-Arbol([uint32]$Id) {
    $ids = New-Object System.Collections.Generic.List[uint32]
    $ids.Add($Id)
    if ($script:Nativo) { foreach ($d in [VeladorNativo]::Descendientes($Id)) { $ids.Add($d) } }
    else {
        try {
            $todos = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, CreationDate -ErrorAction Stop)
            $ini = @{}; foreach ($p in $todos) { $ini[[uint32]$p.ProcessId] = $p.CreationDate }
            $cola = New-Object System.Collections.Queue; $cola.Enqueue($Id)
            while ($cola.Count -gt 0) {
                $x = [uint32]$cola.Dequeue()
                foreach ($p in $todos) {
                    $pi = [uint32]$p.ProcessId
                    if ([uint32]$p.ParentProcessId -eq $x -and $pi -ne $Id -and -not $ids.Contains($pi) -and $ini[$x] -and $p.CreationDate -ge $ini[$x]) { $ids.Add($pi); $cola.Enqueue($pi) }
                }
            }
        } catch {}
    }
    $n = 0
    foreach ($i in $ids) {
        if ($i -eq $PID) { continue }
        try { Stop-Process -Id $i -Force -ErrorAction Stop; $n++ } catch {}
    }
    return $n
}

function Avisar([string]$Nivel, [string]$Titulo, [string]$Detalle) {
    $k = "$Nivel|$Titulo"; $ahora = Get-Date
    if ($script:Vistas.ContainsKey($k) -and ($ahora - $script:Vistas[$k]).TotalSeconds -lt 30) { return }
    $script:Vistas[$k] = $ahora
    Escribir-Registro $Nivel ("{0} -- {1}" -f $Titulo, $Detalle)
    if ($script:Consola) { Write-Host ("ALERTA [{0}] {1} -- {2}" -f $Nivel, $Titulo, $Detalle) }
    elseif ($script:Icono) {
        $ic = [System.Windows.Forms.ToolTipIcon]::Warning; if ($Nivel -eq 'ALTO') { $ic = [System.Windows.Forms.ToolTipIcon]::Error }
        $t = $Detalle; if ($t.Length -gt 230) { $t = $t.Substring(0, 230) + '...' }
        $tit = 'Velador: ' + $Titulo; if ($tit.Length -gt 62) { $tit = $tit.Substring(0, 62) }
        try { $script:Icono.ShowBalloonTip(15000, $tit, $t, $ic) } catch {}
        if ($Nivel -eq 'ALTO') { try { $script:Icono.Text = 'Velador: hubo alertas (ver el registro)' } catch {} }
    }
}

function Actuar($V, $P, [string]$Cl) {
    $quien = [string]$P[2]
    $objetivo = [uint32]$P[0]; if ($V.Raiz -eq 'padre') { $objetivo = [uint32]$P[1] }
    if (Esta-Permitido ("{0} {1}" -f $P[3], $Cl)) { Escribir-Registro 'INFO' ("Permitido por configuración: {0} {1}" -f $quien, $Cl); return }
    $hecho = ''
    if ($V.Matar) {
        if ($script:Config.SoloAvisar) { $hecho = 'Solo se avisa: así está configurado.' }
        else {
            $n = Detener-Arbol $objetivo
            if ($n -gt 0) { $hecho = "Velador lo detuvo ($n proceso(s))." } else { $hecho = 'No se pudo detener: puede que corra con permiso de administrador.' }
        }
    }
    $extra = ''
    if ($quien -ieq 'MSBuild.exe' -and $Cl) {
        $proy = @(Extraer-Rutas $Cl | Where-Object { $_ -notmatch '(?i)msbuild\.exe$' }) | Select-Object -First 1
        if ($proy) {
            $dir = $proy; try { if (Test-Path -LiteralPath $proy -PathType Leaf) { $dir = Split-Path -Parent $proy } } catch {}
            $conf = $false
            try {
                foreach ($f in @(Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction SilentlyContinue | Where-Object { $script:ExtProyecto -contains $_.Extension.ToLower() } | Select-Object -First 12)) {
                    if (@(Buscar-IndicadoresProyecto $f.FullName | Where-Object { $_.Fuerte }).Count -gt 0) { $conf = $true; break }
                }
            } catch {}
            if ($conf) { $extra = ' Confirmado: el proyecto trae un programa oculto. Abre Velador y elige Limpiar.' }
            else { $extra = ' El proyecto no trae señas claras; si era tuyo, agrégalo a Permitidos en config.json.' }
        }
    }
    Avisar $V.Nivel ("{0}: {1}" -f $quien, $V.Motivo) (($hecho + $extra + ' Orden: ' + $Cl).Trim())
}

function Evaluar-ProcesoNuevo($P) {
    $id = [uint32]$P[0]
    if ($id -eq $PID -or $id -le 4) { return }
    $nom = ([string]$P[2]).ToLower(); $ruta = [string]$P[3]; $padre = ([string]$P[4]).ToLower()
    $cl = ''; $clPadre = ''
    $porRuta = ($ruta -and ($ruta -match $script:RxCacheWin))
    $porNombre = ($script:HostsNet -contains $nom) -or ($script:VigilarNombre -contains $nom) -or ($padre -eq 'conhost.exe' -and ($script:Interpretes -contains $nom))
    if ($porNombre) {
        $cl = Linea-Comando $id
        if ($padre -eq 'conhost.exe' -or $padre -eq 'cmd.exe') { $clPadre = Linea-Comando ([uint32]$P[1]) }
    }
    if ($porRuta -or $porNombre) {
        $v = Clasificar-Proceso ([string]$P[2]) $ruta $cl ([string]$P[4]) $clPadre
        if ($v) { Actuar $v $P $cl; return }
    }
    if ($ruta -and ($ruta -match $script:RxLanzado)) {
        $dir = ''; try { $dir = Split-Path -Parent $ruta } catch {}
        if (-not $dir) { return }
        $cands = @($dir); try { $cands += (Split-Path -Parent $dir); $cands += (Split-Path -Parent (Split-Path -Parent $dir)) } catch {}
        foreach ($d in @($cands | Where-Object { $_ })) {
            $k = $d.ToLower()
            if (-not $script:DirsRevisados.ContainsKey($k)) { $r = $null; try { $r = Probar-InstaladorFalso $d } catch {}; if ($r) { $script:DirsRevisados[$k] = $r } else { $script:DirsRevisados[$k] = $false } }
            $f = $script:DirsRevisados[$k]
            if ($f -and $f.Fuerte) {
                $v = Nuevo-Veredicto 'ALTO' $true 'propio' ('es un instalador falso: ' + (@($f.Evidencia) -join '; '))
                Actuar $v $P $ruta
                return
            }
        }
        if ($script:AvApagado) {
            $firma = 'sin firma'; try { if ((Get-AuthenticodeSignature -LiteralPath $ruta -ErrorAction Stop).Status -eq 'Valid') { $firma = 'con firma válida' } } catch {}
            if ($firma -eq 'sin firma') { Avisar 'MEDIO' ("Abriste un programa sin firma con el antivirus apagado: {0}" -f $P[2]) ("{0}. Nadie lo revisó. Si un instalador te pidió apagar el antivirus, desconfía." -f $ruta) }
        }
    }
}

function Nuevos-Lento {
    $r = @(); $ahora = @{}
    $todos = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath -ErrorAction SilentlyContinue)
    $porId = @{}; foreach ($p in $todos) { $porId[[uint32]$p.ProcessId] = $p }
    foreach ($p in $todos) {
        $id = [uint32]$p.ProcessId; $ahora[$id] = [string]$p.Name
        if (-not $script:FotoLenta.ContainsKey($id) -or $script:FotoLenta[$id] -ne [string]$p.Name) {
            $padre = ''; $pp = $porId[[uint32]$p.ParentProcessId]; if ($pp) { $padre = [string]$pp.Name }
            $r += , @([string]$id, [string]$p.ParentProcessId, [string]$p.Name, [string]$p.ExecutablePath, $padre, '')
        }
    }
    $script:FotoLenta = $ahora
    return $r
}

function Listar-CachesRaiz {
    $raiz = $script:RaizCache; if (-not $raiz) { $raiz = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows' }
    $r = @()
    foreach ($n in @('Caches', 'WebCache', 'INetCache', 'History')) {
        $d = Join-Path $raiz $n
        try { foreach ($f in [IO.Directory]::GetFiles($d)) { if ($script:ExtEjecutable -contains [IO.Path]::GetExtension($f).ToLower()) { $r += $f } } } catch {}
    }
    return $r
}

function Revisar-CachesVivo {
    foreach ($f in @(Listar-CachesRaiz)) {
        $k = $f.ToLower()
        if ($script:CacheBase.ContainsKey($k)) { continue }
        $script:CacheBase[$k] = 1
        Avisar 'ALTO' 'Apareció un archivo ejecutable en una carpeta de caché de Windows' ("{0}. Abre Velador y elige Revisar." -f $f)
    }
}

function Huella-Tarea($T) {
    return ($T.Completa + '|' + ((@($T.Acciones) | ForEach-Object { $_.Exe + ' ' + $_.Argumentos }) -join '|')).ToLower()
}

function Revisar-TareasVivo {
    foreach ($t in @(Obtener-Tareas)) {
        $k = Huella-Tarea $t
        if ($script:TareasBase.ContainsKey($k)) { continue }
        $script:TareasBase[$k] = 1
        $h = Evaluar-Tarea $t
        if ($h) { Avisar $h.Nivel ("Se creó una tarea programada sospechosa: {0}" -f $t.Completa) ((@($h.Evidencia) -join '; ') + '. Abre Velador y elige Revisar.') }
    }
}

function Antivirus-Apagado {
    try {
        $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' -ErrorAction Stop).DisableRealtimeMonitoring
        return ($null -ne $v -and [int]$v -eq 1)
    } catch { return $false }
}

function Paso-Vigilante {
    $script:Tick++
    $nuevos = @()
    if ($script:Nativo) { $nuevos = [VeladorNativo]::Nuevos() }
    elseif (($script:Tick % 6) -eq 1) { $nuevos = @(Nuevos-Lento) }
    foreach ($p in $nuevos) {
        try { Evaluar-ProcesoNuevo $p } catch { Escribir-Registro 'ERROR' ('proceso: ' + $_.Exception.Message) }
    }
    if (($script:Tick % 15) -eq 0) {
        try { Revisar-CachesVivo } catch {}
        $ap = Antivirus-Apagado
        if ($ap -and -not $script:AvApagado) { Avisar 'MEDIO' 'El antivirus se acaba de apagar' 'Mientras esté apagado nadie revisa lo que abras. Ningún programa legítimo pide apagarlo.' }
        $script:AvApagado = $ap
    }
    if (($script:Tick % 180) -eq 0) { try { Revisar-TareasVivo } catch {} }
}

function Nombre-Mutex { if ($script:Consola) { return 'Local\VeladorVigilantePrueba' }; return 'Local\VeladorVigilante' }
function Nombre-Evento { if ($script:Consola) { return 'Local\VeladorSalirPrueba' }; return 'Local\VeladorSalir' }

function Vigilante-Encendido {
    try { $m = [System.Threading.Mutex]::OpenExisting('Local\VeladorVigilante'); $m.Dispose(); return $true } catch { return $false }
}

function Apagar-Vigilante {
    try { $e = [System.Threading.EventWaitHandle]::OpenExisting('Local\VeladorSalir'); [void]$e.Set(); $e.Dispose(); return $true } catch { return $false }
}

function Encender-VigilanteOculto {
    if (Vigilante-Encendido) { return }
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @('-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $script:Yo), 'vigilar') | Out-Null
}

function Iniciar-Vigilante {
    $creado = $false
    $script:Mutex = New-Object System.Threading.Mutex($true, (Nombre-Mutex), [ref]$creado)
    if (-not $creado) { Write-Host 'El vigilante ya está encendido.'; return }
    $script:EvSalir = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, (Nombre-Evento))
    [void]$script:EvSalir.Reset()
    $script:Nativo = Cargar-Nativo
    $script:Vistas = @{}; $script:DirsRevisados = @{}; $script:FotoLenta = @{}; $script:Tick = 0
    $script:TareasBase = @{}; foreach ($t in @(Obtener-Tareas)) { $script:TareasBase[(Huella-Tarea $t)] = 1 }
    $script:CacheBase = @{}; foreach ($f in @(Listar-CachesRaiz)) { $script:CacheBase[$f.ToLower()] = 1 }
    $script:AvApagado = Antivirus-Apagado
    Escribir-Registro 'INFO' ("Vigilante encendido (versión {0}, nativo={1})" -f $script:Version, $script:Nativo)

    if ($script:Consola) {
        Paso-Vigilante
        $fin = [datetime]::MaxValue; if ($script:Segundos -gt 0) { $fin = (Get-Date).AddSeconds($script:Segundos) }
        Write-Host 'VIGILANTE-LISTO'
        while ((Get-Date) -lt $fin -and -not $script:EvSalir.WaitOne(0)) { Start-Sleep -Milliseconds 300; Paso-Vigilante }
    }
    else {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $script:Icono = New-Object System.Windows.Forms.NotifyIcon
        $script:Icono.Icon = [System.Drawing.SystemIcons]::Shield
        $script:Icono.Text = 'Velador: vigilando'
        $script:Icono.Visible = $true
        $menu = New-Object System.Windows.Forms.ContextMenuStrip
        $m1 = $menu.Items.Add('Ver el registro'); $m1.add_Click({ try { Start-Process notepad.exe $script:Registro } catch {} })
        $m2 = $menu.Items.Add('Abrir Velador'); $m2.add_Click({ try { Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $script:Yo)) } catch {} })
        $m3 = $menu.Items.Add('Apagar el vigilante'); $m3.add_Click({ [void]$script:EvSalir.Set() })
        $script:Icono.ContextMenuStrip = $menu
        $script:Reloj = New-Object System.Windows.Forms.Timer
        $script:Reloj.Interval = 350
        $script:Reloj.add_Tick({
                try {
                    if ($script:EvSalir.WaitOne(0)) { $script:Reloj.Stop(); [System.Windows.Forms.Application]::Exit(); return }
                    Paso-Vigilante
                } catch { Escribir-Registro 'ERROR' ('vigilante: ' + $_.Exception.Message) }
            })
        Paso-Vigilante
        $pend = @($script:TareasBase.Keys).Count
        try { $script:Icono.ShowBalloonTip(6000, 'Velador', 'El vigilante está encendido.', [System.Windows.Forms.ToolTipIcon]::Info) } catch {}
        $script:Reloj.Start()
        [System.Windows.Forms.Application]::Run()
        try { $script:Icono.Visible = $false; $script:Icono.Dispose() } catch {}
    }
    Escribir-Registro 'INFO' 'Vigilante apagado'
    try { $script:Mutex.ReleaseMutex() } catch {}
    try { $script:Mutex.Dispose(); $script:EvSalir.Dispose() } catch {}
}

# ---------------------------------------------------------------------------------------------
#  Arranque del vigilante con Windows (acceso directo en la carpeta Inicio del usuario)
# ---------------------------------------------------------------------------------------------
function Ruta-AccesoArranque { return (Join-Path ([Environment]::GetFolderPath('Startup')) 'Velador.lnk') }

function Poner-Arranque {
    $destDir = Join-Path $script:Datos 'app'
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    $dest = Join-Path $destDir 'velador.ps1'
    if ($script:Yo -ne $dest) { Copy-Item -LiteralPath $script:Yo -Destination $dest -Force }
    $sh = New-Object -ComObject WScript.Shell
    $l = $sh.CreateShortcut((Ruta-AccesoArranque))
    $l.TargetPath = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
    $l.Arguments = ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" vigilar' -f $dest)
    $l.WindowStyle = 7
    $l.Description = 'Velador: vigilante'
    $l.Save()
    Escribir-Registro 'INFO' 'Arranque con Windows activado'
}

function Quitar-Arranque {
    $p = Ruta-AccesoArranque
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force; Escribir-Registro 'INFO' 'Arranque con Windows quitado' }
}

# ---------------------------------------------------------------------------------------------
#  Blindaje (reversible)
# ---------------------------------------------------------------------------------------------
function Lista-ProgramasCortafuegos {
    $r = @()
    $net = @('MSBuild.exe', 'RegAsm.exe', 'RegSvcs.exe', 'InstallUtil.exe', 'AddInProcess.exe', 'AddInProcess32.exe', 'AddInUtil.exe', 'aspnet_compiler.exe', 'CasPol.exe', 'ilasm.exe', 'jsc.exe', 'vbc.exe', 'csc.exe', 'cvtres.exe', 'AppLaunch.exe', 'Microsoft.Workflow.Compiler.exe', 'IEExec.exe')
    foreach ($fw in @('Framework', 'Framework64')) {
        foreach ($v in @('v4.0.30319', 'v3.5', 'v2.0.50727')) {
            $d = Join-Path $env:WINDIR ("Microsoft.NET\{0}\{1}" -f $fw, $v)
            if (-not (Test-Path -LiteralPath $d)) { continue }
            foreach ($n in $net) { $p = Join-Path $d $n; if (Test-Path -LiteralPath $p -PathType Leaf) { $r += $p } }
        }
    }
    $sys = @('mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'certutil.exe', 'cmstp.exe', 'hh.exe', 'finger.exe', 'forfiles.exe', 'conhost.exe', 'odbcconf.exe', 'pcalua.exe', 'InfDefaultInstall.exe', 'presentationhost.exe', 'xwizard.exe')
    foreach ($d in @((Join-Path $env:WINDIR 'System32'), (Join-Path $env:WINDIR 'SysWOW64'))) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($n in $sys) { $p = Join-Path $d $n; if (Test-Path -LiteralPath $p -PathType Leaf) { $r += $p } }
    }
    return $r
}

function Nombre-Regla([string]$Programa) {
    $dir = Split-Path -Parent $Programa
    $corto = (Split-Path -Leaf (Split-Path -Parent $dir)) + '\' + (Split-Path -Leaf $dir)
    if ($dir -match '(?i)\\(System32|SysWOW64)$') { $corto = Split-Path -Leaf $dir }
    return ('Velador - sin internet: {0} [{1}]' -f (Split-Path -Leaf $Programa), $corto)
}

function Mostrar-PlanBlindaje {
    $progs = @(Lista-ProgramasCortafuegos)
    $bloq = @($script:ReglasASR | Where-Object { $_.Accion -eq 1 }).Count
    $reg = @($script:ReglasASR | Where-Object { $_.Accion -eq 2 }).Count
    Write-Host ''
    Write-Host '  BLINDAR ESTA COMPUTADORA' -ForegroundColor Cyan
    Write-Host '  Todo esto se puede deshacer después desde el menú.'
    Write-Host ''
    Write-Host ("  1. Cortafuegos: quitarles la salida a internet a {0} programas de Windows que el malware usa de disfraz" -f $progs.Count)
    Write-Host '     (MSBuild, RegAsm, InstallUtil, mshta, wscript, certutil...). Siguen funcionando; solo no pueden conectarse.'
    Write-Host '  2. Antivirus de Windows: bloquear programas no deseados, subir la protección en la nube a nivel alto'
    Write-Host ("     y activar {0} reglas contra técnicas de ataque ({1} bloquean, {2} solo registran)." -f $script:ReglasASR.Count, $bloq, $reg)
    Write-Host '  3. Archivos de órdenes: que un doble clic en archivos .js, .vbs o .hta los abra en el Bloc de notas'
    Write-Host '     en vez de ejecutarlos.'
    Write-Host ''
    if ($script:Simular) {
        Write-Host '  Detalle del punto 1 (una regla de salida bloqueada por programa):'
        foreach ($p in $progs) { Write-Host ("     New-NetFirewallRule -Group Velador -Direction Outbound -Action Block -Program `"{0}`"" -f $p) }
        Write-Host ''
        Write-Host '  Detalle del punto 2:'
        Write-Host '     Set-MpPreference -PUAProtection 1'
        Write-Host '     Set-MpPreference -CloudBlockLevel 2 -CloudExtendedTimeout 50'
        foreach ($r in $script:ReglasASR) { $a = 'bloquear'; if ($r.Accion -eq 2) { $a = 'registrar' }; Write-Host ("     regla {0} = {1,-9} {2}" -f $r.Id, $a, $r.Nombre) }
        Write-Host ''
        Write-Host '  Detalle del punto 3 (en tu usuario):'
        foreach ($c in $script:ClasesScript) { Write-Host ("     HKCU\Software\Classes\{0}\Shell\Open\Command = Bloc de notas" -f $c) }
        Write-Host ''
    }
}

function Aplicar-BlindajeUsuario([string]$RaizReg = 'HKCU:\Software\Classes', [string[]]$Clases = $script:ClasesScript) {
    $estado = Join-Path $script:Datos 'blindaje-usuario.json'
    $prev = [ordered]@{}
    foreach ($c in $Clases) {
        $k = Join-Path $RaizReg ("{0}\Shell\Open\Command" -f $c)
        $antes = $null
        if (Test-Path -Path $k) { try { $antes = (Get-ItemProperty -Path $k -ErrorAction Stop).'(default)' } catch {} }
        $prev[$c] = $antes
        if ($script:Simular) { continue }
        try {
            New-Item -Path $k -Force -ErrorAction Stop | Out-Null
            Set-ItemProperty -Path $k -Name '(default)' -Value ('"{0}\System32\notepad.exe" "%1"' -f $env:SystemRoot) -ErrorAction Stop
        } catch { Write-Host ("   No se pudo cambiar {0}: {1}" -f $c, $_.Exception.Message) -ForegroundColor Yellow }
    }
    if (-not $script:Simular) {
        if (-not (Test-Path -LiteralPath $estado)) { ([pscustomobject]$prev | ConvertTo-Json) | Set-Content -LiteralPath $estado -Encoding UTF8 }
        Write-Host '   Archivos de órdenes: ahora se abren en el Bloc de notas.' -ForegroundColor Green
        Escribir-Registro 'INFO' 'Blindaje de usuario aplicado'
    }
}

function Quitar-BlindajeUsuario([string]$RaizReg = 'HKCU:\Software\Classes', [string[]]$Clases = $script:ClasesScript) {
    $estado = Join-Path $script:Datos 'blindaje-usuario.json'
    if (-not (Test-Path -LiteralPath $estado)) { Write-Host '   Archivos de órdenes: no había cambios de Velador.'; return }
    $prev = $null; try { $prev = Get-Content -LiteralPath $estado -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
    foreach ($c in $Clases) {
        $k = Join-Path $RaizReg ("{0}\Shell\Open\Command" -f $c)
        $antes = $null; if ($prev) { $antes = $prev.$c }
        if ($script:Simular) { continue }
        try {
            if ($antes) { Set-ItemProperty -Path $k -Name '(default)' -Value ([string]$antes) -ErrorAction Stop }
            elseif (Test-Path -Path $k) {
                Remove-Item -Path $k -Force -ErrorAction Stop
                foreach ($sub in @('Shell\Open', 'Shell', '')) {
                    $kk = Join-Path $RaizReg $c; if ($sub) { $kk = Join-Path $kk $sub }
                    if (-not (Test-Path -Path $kk)) { continue }
                    $it = Get-Item -Path $kk
                    if ($it.SubKeyCount -eq 0 -and $it.ValueCount -eq 0) { Remove-Item -Path $kk -Force } else { break }
                }
            }
        } catch { Write-Host ("   No se pudo restaurar {0}: {1}" -f $c, $_.Exception.Message) -ForegroundColor Yellow }
    }
    if (-not $script:Simular) {
        Remove-Item -LiteralPath $estado -Force -ErrorAction SilentlyContinue
        Write-Host '   Archivos de órdenes: restaurados como estaban.' -ForegroundColor Green
        Escribir-Registro 'INFO' 'Blindaje de usuario quitado'
    }
}

function Aplicar-BlindajeSistema {
    if ($script:Simular) { return }
    if (-not (Es-Admin)) { Write-Host '   Hace falta permiso de administrador para el cortafuegos y el antivirus.' -ForegroundColor Yellow; return }
    $dirEstado = Join-Path $env:ProgramData 'Velador'; $archEstado = Join-Path $dirEstado 'blindaje.json'
    New-Item -ItemType Directory -Force -Path $dirEstado | Out-Null

    Write-Host ''
    Write-Host '  Cortafuegos...' -ForegroundColor Cyan
    $existentes = @{}
    try { foreach ($r in @(Get-NetFirewallRule -Group 'Velador' -ErrorAction Stop)) { $existentes[$r.DisplayName] = 1 } } catch {}
    $hechas = 0; $ya = 0; $fallas = 0
    foreach ($p in @(Lista-ProgramasCortafuegos)) {
        $nombre = Nombre-Regla $p
        if ($existentes.ContainsKey($nombre)) { $ya++; continue }
        try {
            New-NetFirewallRule -DisplayName $nombre -Group 'Velador' -Description 'Velador: este programa de Windows no necesita internet y el malware lo usa de disfraz.' -Direction Outbound -Action Block -Program $p -Profile Any -ErrorAction Stop | Out-Null
            $hechas++
        } catch { $fallas++; Write-Host ("   No se pudo crear la regla de {0}: {1}" -f $p, $_.Exception.Message) -ForegroundColor Yellow }
    }
    Write-Host ("   Reglas nuevas: {0}. Ya estaban: {1}. Fallaron: {2}." -f $hechas, $ya, $fallas) -ForegroundColor Green

    Write-Host ''
    Write-Host '  Antivirus de Windows...' -ForegroundColor Cyan
    $st = $null; try { $st = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if (-not $st -or ([string]$st.AMRunningMode) -notmatch 'Normal') {
        Write-Host '   Microsoft Defender no es tu antivirus activo; esta parte se omite.' -ForegroundColor Yellow
    }
    else {
        $pref = Get-MpPreference
        if (-not (Test-Path -LiteralPath $archEstado)) {
            $snap = [ordered]@{
                Fecha = (Get-Date).ToString('o')
                Defender = [ordered]@{
                    PUAProtection = [int]$pref.PUAProtection; CloudBlockLevel = [int]$pref.CloudBlockLevel; CloudExtendedTimeout = [int]$pref.CloudExtendedTimeout; MAPSReporting = [int]$pref.MAPSReporting
                    AsrIds = @($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ }); AsrActions = @($pref.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
                }
            }
            ConvertTo-Json -InputObject $snap -Depth 5 | Set-Content -LiteralPath $archEstado -Encoding UTF8
        }
        try { Set-MpPreference -PUAProtection 1 -ErrorAction Stop; Write-Host '   Bloqueo de programas no deseados: activado.' -ForegroundColor Green } catch { Write-Host ("   Programas no deseados: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
        if ([int]$pref.MAPSReporting -eq 0) { try { Set-MpPreference -MAPSReporting 2 -ErrorAction Stop; Write-Host '   Protección en la nube: activada.' -ForegroundColor Green } catch {} }
        try { Set-MpPreference -CloudBlockLevel 2 -CloudExtendedTimeout 50 -ErrorAction Stop; Write-Host '   Protección en la nube: nivel alto.' -ForegroundColor Green } catch { Write-Host ("   Nivel de nube: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
        if ($pref.DisableRealtimeMonitoring) { try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; Write-Host '   Protección en tiempo real: encendida.' -ForegroundColor Green } catch {} }
        $mapa = [ordered]@{}
        $ids = @($pref.AttackSurfaceReductionRules_Ids); $acts = @($pref.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $mapa[([string]$ids[$i]).ToLower()] = [int]$acts[$i] } }
        foreach ($r in $script:ReglasASR) {
            $k = $r.Id.ToLower()
            if (-not $mapa.Contains($k) -or [int]$mapa[$k] -eq 0 -or ([int]$mapa[$k] -eq 2 -and $r.Accion -eq 1)) { $mapa[$k] = [int]$r.Accion }
        }
        try {
            Set-MpPreference -AttackSurfaceReductionRules_Ids ([string[]]@($mapa.Keys)) -AttackSurfaceReductionRules_Actions ([int[]]@($mapa.Values)) -ErrorAction Stop
            Write-Host ("   Reglas contra técnicas de ataque: {0} activas." -f $mapa.Count) -ForegroundColor Green
        } catch { Write-Host ("   Reglas de ataque: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
        if ($st.PSObject.Properties['IsTamperProtected'] -and -not $st.IsTamperProtected) {
            Write-Host '   OJO: la protección contra alteraciones está apagada y solo se puede encender a mano:' -ForegroundColor Yellow
            Write-Host '        Seguridad de Windows > Protección contra virus y amenazas > Administrar la configuración.'
        }
        if (-not $st.FullScanEndTime) {
            $r = ''; try { $r = Read-Host '   Nunca se ha hecho un examen completo. ¿Iniciarlo ahora en segundo plano? Tarda horas (S/N)' } catch {}
            if ($r -match '^\s*(s|si|sí)\s*$') {
                $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
                try { Start-Process -FilePath $mp -ArgumentList @('-Scan', '-ScanType', '2') -WindowStyle Hidden; Write-Host '   Examen completo iniciado.' -ForegroundColor Green } catch { Write-Host '   No se pudo iniciar el examen.' -ForegroundColor Yellow }
            }
        }
    }
    Escribir-Registro 'INFO' 'Blindaje de sistema aplicado'
    Write-Host ''
    Write-Host '  Blindaje aplicado.' -ForegroundColor Green
}

function Quitar-BlindajeSistema {
    if ($script:Simular) { return }
    if (-not (Es-Admin)) { Write-Host '   Hace falta permiso de administrador para el cortafuegos y el antivirus.' -ForegroundColor Yellow; return }
    $archEstado = Join-Path (Join-Path $env:ProgramData 'Velador') 'blindaje.json'
    $n = 0; try { $n = @(Get-NetFirewallRule -Group 'Velador' -ErrorAction Stop).Count; Remove-NetFirewallRule -Group 'Velador' -ErrorAction Stop } catch {}
    Write-Host ("   Cortafuegos: {0} regla(s) quitadas." -f $n) -ForegroundColor Green
    if (Test-Path -LiteralPath $archEstado) {
        $e = $null; try { $e = Get-Content -LiteralPath $archEstado -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
        if ($e -and $e.Defender) {
            $d = $e.Defender
            try { Set-MpPreference -PUAProtection ([int]$d.PUAProtection) -CloudBlockLevel ([int]$d.CloudBlockLevel) -CloudExtendedTimeout ([int]$d.CloudExtendedTimeout) -MAPSReporting ([int]$d.MAPSReporting) -ErrorAction Stop } catch { Write-Host ("   Antivirus: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
            $prevIds = @($d.AsrIds | Where-Object { $_ })
            try {
                if ($prevIds.Count -gt 0) { Set-MpPreference -AttackSurfaceReductionRules_Ids ([string[]]$prevIds) -AttackSurfaceReductionRules_Actions ([int[]]@($d.AsrActions)) -ErrorAction Stop }
                else { Remove-MpPreference -AttackSurfaceReductionRules_Ids ([string[]]@($script:ReglasASR | ForEach-Object { $_.Id })) -ErrorAction Stop }
            } catch { Write-Host ("   Reglas de ataque: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
            Write-Host '   Antivirus: configuración anterior restaurada.' -ForegroundColor Green
        }
        Remove-Item -LiteralPath $archEstado -Force -ErrorAction SilentlyContinue
    }
    Escribir-Registro 'INFO' 'Blindaje de sistema quitado'
}

function Relanzar-Elevado([string]$ModoElevado) {
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $script:Yo), $ModoElevado, '-Elevado') | Out-Null
        Write-Host '  Se abrió otra ventana con permiso de administrador; ahí verás el resultado.'
    } catch { Write-Host '  No se dio el permiso de administrador; esa parte no se aplicó.' -ForegroundColor Yellow }
}

function Hacer-Blindaje {
    if ($script:Elevado) { Aplicar-BlindajeSistema; Pausa-Final; return }
    Mostrar-PlanBlindaje
    if ($script:Simular) { Write-Host '  Simulación: no se cambió nada.'; return }
    if (-not (Confirmar '  ¿Aplicar el blindaje? Windows te va a pedir permiso de administrador')) { Write-Host '  No se cambió nada.'; return }
    Aplicar-BlindajeUsuario
    if (Es-Admin) { Aplicar-BlindajeSistema } else { Relanzar-Elevado 'blindar' }
}

function Hacer-Desblindaje {
    if ($script:Elevado) { Quitar-BlindajeSistema; Pausa-Final; return }
    if ($script:Simular) { Write-Host '  Simulación: se quitarían las reglas del cortafuegos del grupo Velador y se restauraría la configuración anterior.'; return }
    if (-not (Confirmar '  ¿Quitar el blindaje y dejar todo como estaba?')) { Write-Host '  No se cambió nada.'; return }
    Quitar-BlindajeUsuario
    if (Es-Admin) { Quitar-BlindajeSistema } else { Relanzar-Elevado 'desblindar' }
}

# ---------------------------------------------------------------------------------------------
#  Estado y menú
# ---------------------------------------------------------------------------------------------
function Obtener-Estado {
    $fw = 0; try { $fw = @(Get-NetFirewallRule -Group 'Velador' -ErrorAction Stop).Count } catch {}
    $av = 'desconocido'
    try { $st = Get-MpComputerStatus -ErrorAction Stop; if ($st.RealTimeProtectionEnabled) { $av = 'encendido' } else { $av = 'APAGADO' } } catch {}
    return [pscustomobject]@{
        Vigilante = (Vigilante-Encendido)
        Arranque = (Test-Path -LiteralPath (Ruta-AccesoArranque))
        ReglasCortafuegos = $fw
        BlindajeUsuario = (Test-Path -LiteralPath (Join-Path $script:Datos 'blindaje-usuario.json'))
        Antivirus = $av
    }
}

function Mostrar-Estado {
    $e = Obtener-Estado
    $v = 'apagado'; if ($e.Vigilante) { $v = 'ENCENDIDO' }
    $a = 'no'; if ($e.Arranque) { $a = 'sí' }
    $b = 'no aplicado'; if ($e.ReglasCortafuegos -gt 0) { $b = "aplicado ($($e.ReglasCortafuegos) reglas)" }
    Write-Host ("  Vigilante: {0}     Arranca con Windows: {1}" -f $v, $a)
    Write-Host ("  Blindaje:  {0}     Antivirus: {1}" -f $b, $e.Antivirus)
    return $e
}

function Mostrar-Menu {
    while ($true) {
        try { Clear-Host } catch {}
        Write-Host ''
        Write-Host ("  VELADOR {0}" -f $script:Version) -ForegroundColor Cyan
        Write-Host '  Guardia contra instaladores falsos y programas que se cargan a escondidas'
        Write-Host ''
        $e = Mostrar-Estado
        Write-Host ''
        Write-Host '   1. Revisar esta computadora (no cambia nada)'
        Write-Host '   2. Blindar (pide permiso de administrador; se puede deshacer)'
        if ($e.Vigilante) { Write-Host '   3. Apagar el vigilante' } else { Write-Host '   3. Encender el vigilante' }
        if ($e.Arranque) { Write-Host '   4. Que el vigilante ya no arranque con Windows' } else { Write-Host '   4. Que el vigilante arranque solo con Windows' }
        Write-Host '   5. Limpiar: mandar a cuarentena lo grave'
        Write-Host '   6. Restaurar la última cuarentena'
        Write-Host '   7. Quitar el blindaje'
        Write-Host '   8. Ver el registro'
        Write-Host '   0. Salir'
        Write-Host ''
        $op = ''; try { $op = (Read-Host '  Elige una opción').Trim() } catch { return }
        switch ($op) {
            '1' { [void](Hacer-Revision) }
            '2' { Hacer-Blindaje }
            '3' { if ($e.Vigilante) { [void](Apagar-Vigilante); Write-Host '  Vigilante apagado.' } else { Encender-VigilanteOculto; Write-Host '  Vigilante encendido: busca el escudo junto al reloj.' } }
            '4' { if ($e.Arranque) { Quitar-Arranque; Write-Host '  Ya no arranca con Windows.' } else { Poner-Arranque; Encender-VigilanteOculto; Write-Host '  Listo: el vigilante arrancará solo cada vez que inicies sesión.' } }
            '5' { Ejecutar-Limpieza }
            '6' { Ejecutar-Restauracion }
            '7' { Hacer-Desblindaje }
            '8' { if (Test-Path -LiteralPath $script:Registro) { Start-Process notepad.exe $script:Registro } else { Write-Host '  Todavía no hay registro.' } }
            '0' { return }
            default { }
        }
        if ($op -ne '0') { try { [void](Read-Host '  Enter para volver al menú') } catch { return } }
    }
}

# ---------------------------------------------------------------------------------------------
#  Entrada
# ---------------------------------------------------------------------------------------------
$script:Config = Leer-Config
switch ($Modo.ToLower()) {
    'funciones' { }
    'revisar' {
        $h = @(Hacer-Revision)
        if (@($h | Where-Object { $_.Nivel -eq 'ALTO' }).Count -gt 0) { exit 2 }
        if (@($h | Where-Object { $_.Nivel -eq 'MEDIO' }).Count -gt 0) { exit 1 }
        exit 0
    }
    'vigilar' { Iniciar-Vigilante }
    'apagar' { if (Apagar-Vigilante) { Write-Host 'Vigilante apagado.' } else { Write-Host 'El vigilante no estaba encendido.' } }
    'blindar' { Hacer-Blindaje }
    'desblindar' { Hacer-Desblindaje }
    'limpiar' { Ejecutar-Limpieza }
    'restaurar' { Ejecutar-Restauracion }
    'estado' { [void](Mostrar-Estado) }
    'menu' { Mostrar-Menu }
    default { Write-Host 'Modos: revisar, vigilar, apagar, blindar, desblindar, limpiar, restaurar, estado' }
}
