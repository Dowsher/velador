# Guía para desarrolladores

Velador es un solo archivo de PowerShell (`velador.ps1`), sin dependencias. Esta guía explica cómo
está armado, cómo probarlo y qué se pide en un cambio.

## Requisitos

- Windows 10 u 11 con el PowerShell 5.1 que ya trae. No hay que instalar nada.
- El código debe correr en una PC recién instalada. No uses sintaxis de PowerShell 7 (`??`, `?.`,
  el operador ternario, `&&`) ni módulos que no vengan con Windows.

## Probar

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File pruebas\probar.ps1
```

Corre 62 pruebas en unos segundos, sin permiso de administrador. Trabaja en una carpeta temporal
con casos inofensivos (texto inerte que imita la forma del ataque) y la borra al terminar. Con
`-Conservar` la deja para inspeccionarla; bórrala después, porque una revisión real marcaría esos
casos como hallazgos.

Para ver qué cambiaría el blindaje sin tocar nada:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File velador.ps1 blindar -Simular
```

Para cargar las funciones en una consola y probarlas a mano, sin ejecutar nada más:

```powershell
. .\velador.ps1 funciones -SoloPruebas -Datos "$env:TEMP\velador-dev"
$ms = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
Clasificar-Proceso 'MSBuild.exe' $ms "`"$ms`" `"C:\Users\x\Downloads\algo.csproj`"" 'cmd.exe' ''
```

Devuelve un veredicto (`Nivel`, `Matar`, `Raiz`, `Motivo`) o nada si el proceso no le interesa.

## Cómo está armado `velador.ps1`

De arriba abajo:

1. **Parámetros y reglas.** Las listas y expresiones que definen qué es sospechoso
   (`$script:RxRutaAlta`, `$script:HostsNet`, `$script:ReglasASR` y las demás).
2. **Utilidades y apoyo nativo.** `Cargar-Nativo` compila un ayudante pequeño en C#
   (`VeladorNativo`) que entrega los procesos nuevos desde la última consulta.
3. **Revisión** (modo `revisar`). `Revisar-Tareas`, `Revisar-Inicio`, `Revisar-Carpetas`,
   `Revisar-InstaladoresFalsos`, `Revisar-Procesos` y `Revisar-Proteccion`. El informe lo escribe
   `Escribir-InformeHtml`. No cambia nada en la computadora.
4. **Cuarentena** (modos `limpiar` y `restaurar`).
5. **Vigilante** (modo `vigilar`). Un reloj llama a `Paso-Vigilante` cada 350 ms;
   `Evaluar-ProcesoNuevo` decide y `Actuar` avisa y detiene el árbol de procesos.
6. **Blindaje** (modos `blindar` y `desblindar`). `Aplicar-BlindajeSistema` cambia el cortafuegos y
   el antivirus (pide administrador) y `Aplicar-BlindajeUsuario` cambia cómo se abren los archivos
   de órdenes.
7. **Estado, menú y el `switch` de modos**, al final.

Las decisiones viven en funciones que reciben texto y devuelven un veredicto. Por eso se prueban
sin ejecutar ningún programa:

| Función | Decide sobre |
|---|---|
| `Clasificar-Proceso` | Un proceso que acaba de arrancar: nombre, ruta, orden y proceso padre. |
| `Evaluar-Comando` | Una orden que arranca sola: la de una tarea programada o una entrada de inicio. |
| `Evaluar-Tarea` | Una tarea programada completa. |
| `Buscar-IndicadoresProyecto` | Un archivo de proyecto de MSBuild. |
| `Probar-InstaladorFalso` | Una carpeta con un instalador hecho con Ren'Py. |

## Agregar o cambiar una regla

1. Escribe primero las pruebas en `pruebas\probar.ps1`: un caso que debe detectarse y un caso
   legítimo parecido que debe quedar en paz. Las que ya existen sirven de modelo
   (`Probar 'nombre' { condición }`).
2. Cambia la función.
3. Corre las pruebas completas.

El vigilante **detiene** procesos, así que una falsa alarma cuesta más que una detección perdida.
Una regla que detiene (`Matar` en verdadero) debe describir algo que un programa legítimo no hace.
Si hay duda, que solo avise.

## Reglas del proyecto

- **Un solo archivo, sin dependencias.** Nada de módulos externos ni de descargas.
- **Velador no se conecta a internet.** Ningún cambio debe agregar conexiones: ni actualizaciones
  automáticas, ni estadísticas de uso.
- **Todo cambio al sistema se puede deshacer** y aparece en `blindar -Simular`.
- **`velador.ps1` y `pruebas\probar.ps1` se guardan en UTF-8 con BOM.** Sin esa marca, PowerShell
  5.1 lee mal los acentos. Las pruebas comprueban la de `velador.ps1`.
- **Nada de malware real**, ni en el repositorio ni en los reportes. Los casos de prueba son texto
  inerte. Para una variante nueva basta su SHA-256 y la descripción de las órdenes que lanza.
- **Los textos que ve la persona van en español claro**, sin jerga.

## Reportar una falsa alarma o algo que se escapó

Abre un reporte con:

- La versión de Windows.
- Qué estabas haciendo cuando pasó.
- El renglón de `registro.log` (opción 8 del menú). Quita tu nombre de usuario de las rutas.
- Si es una variante nueva: su SHA-256 y las órdenes que lanza. No adjuntes el archivo.

## Enviar un cambio

Un cambio por solicitud, con sus pruebas, y una explicación del caso real que lo motiva.
