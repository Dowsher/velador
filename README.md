# Velador

Guardia para Windows contra instaladores falsos y programas que se cargan a escondidas.

Nació de un caso real: un "programa portable" pirata que en realidad era un cargador. Usaba
herramientas legítimas de Windows (`conhost`, `forfiles`, `MSBuild`) para armar y ejecutar un
programa oculto en la memoria, sin dejar ningún `.exe` que el antivirus pudiera revisar.
Los investigadores llaman a esta familia *RenPy Loader* o *RenEngine*.

Es gratis y de código abierto. Todo el programa es un solo archivo de texto (`velador.ps1`)
que cualquiera puede leer antes de usarlo.

## Estado

Versión 1.0, recién publicada. Lo que está probado y lo que no:

- **Revisar y el vigilante** se han probado en uso real en una PC con Windows 11. La revisión encontró
  los restos del ataque que dio origen al proyecto y el vigilante detuvo una imitación inofensiva en
  menos de un segundo.
- **Blindar todavía no se ha aplicado en ninguna computadora real.** Sus cambios se han comprobado
  por partes y en simulación, y deshacerlo solo se ha probado en la parte que no pide administrador.
  Antes de usarlo mira qué cambiaría con `Velador.cmd blindar -Simular`, y cuenta cómo te fue.
- En Windows 10 no se ha probado.

## Cómo empezar

1. Descarga el ZIP de Velador. Antes de abrirlo: clic derecho sobre el ZIP > **Propiedades** >
   marca **Desbloquear** > **Aceptar**. Windows marca todo lo que baja de internet; sin este
   paso puede mostrar avisos al abrirlo.
2. Extrae la carpeta donde quieras, por ejemplo en Documentos.
3. Doble clic en **`Velador.cmd`**. Aparece un menú.

No instala nada. Usa el PowerShell que ya trae Windows 10 y 11.

## El menú

| Opción | Qué hace | ¿Cambia algo? |
|---|---|---|
| **1. Revisar** | Busca rastros de este tipo de ataque y abre un informe. | No |
| **2. Blindar** | Cierra las puertas que usa el ataque. Pide permiso de administrador. En pruebas: ver **Estado**. | Sí, y se deshace con la opción 7 |
| **3. Encender el vigilante** | Se queda junto al reloj (un escudo) y detiene el ataque en el momento en que arranca. | No |
| **4. Arrancar con Windows** | Hace que el vigilante se encienda solo cada vez que inicias sesión. | Pone un acceso directo en la carpeta Inicio |
| **5. Limpiar** | Manda a cuarentena lo que la revisión marcó como grave. Pide escribir `SI`. | Mueve archivos; se restauran con la opción 6 |

## Qué reconoce

- Tareas programadas que se disfrazan de programas de Windows o que lanzan archivos desde carpetas del usuario.
- Archivos ejecutables metidos en carpetas donde Windows solo guarda datos (`Caches`, `WebCache`, `INetCache`), ocultos o con fecha falsa.
- Proyectos de MSBuild que traen un programa escondido (en hexadecimal, como lista de números o en base64) o que le ordenan cargarlo en memoria.
- Instaladores falsos armados con el motor de juegos Ren'Py: código anti-análisis, configuración oculta y carga cifrada.
- En vivo: `conhost --headless` lanzando órdenes invisibles, `forfiles` ejecutando a escondidas, MSBuild sobre proyectos en carpetas del usuario, RegAsm/InstallUtil abiertos sin instrucciones, scripts descargados y programas que corren desde la caché de Windows.
- El antivirus apagado, y cuándo se apagó en los últimos 6 meses.

## Qué hace el blindaje

1. **Cortafuegos:** les quita la salida a internet a los programas de Windows que el malware usa de disfraz (MSBuild, RegAsm, InstallUtil, mshta, wscript, certutil y otros). Siguen funcionando; solo no pueden conectarse. No toca PowerShell, `cmd`, `rundll32` ni los navegadores.
2. **Antivirus de Windows:** activa el bloqueo de programas no deseados, sube la protección en la nube a nivel alto y enciende 16 reglas contra técnicas de ataque (13 bloquean, 3 solo registran).
3. **Archivos de órdenes:** un doble clic en `.js`, `.vbs` o `.hta` los abre en el Bloc de notas en vez de ejecutarlos.

Antes de cambiar nada guarda cómo estaba todo, y **Quitar el blindaje** (opción 7) lo regresa. Para ver
exactamente qué cambiaría sin tocar nada: `Velador.cmd blindar -Simular`.

## Lo que Velador no hace

- **No sustituye al antivirus.** Reconoce una forma de ataque y sus parientes cercanos, no todos los virus.
- **No impide que abras un programa pirata.** Reduce el daño si lo haces, pero la única protección completa es no abrirlos, y nunca apagar el antivirus porque un instalador lo pida.
- **No detiene programas que corren como administrador** si Velador no corre también como administrador.
- **Un atacante que conozca Velador puede esquivarlo.** Es un cinturón de seguridad, no una caja fuerte.

## Si el vigilante detiene algo tuyo

Sale un aviso junto al reloj y queda anotado en el registro (opción 8). Puede pasar en dos casos:

- **Programas con Visual Studio.** El vigilante detiene a MSBuild cuando compila un proyecto guardado en Descargas, en la carpeta temporal o en AppData, porque así trabaja este ataque. Si compilas proyectos ahí, muévelos a otra carpeta o agrégala a `Permitidos`.
- **Herramientas antiguas que usan los mismos trucos.** Por ejemplo, archivos `.bat` que piden permiso de administrador con un `.vbs` temporal, o que llaman a `mshta` con código.

Para permitir algo, usa los ajustes de abajo.

## Ajustes

Opcional: crear `%LOCALAPPDATA%\Velador\config.json`.

```json
{ "SoloAvisar": false, "Permitidos": ["C:\\ruta\\de\\un\\proyecto\\mío"] }
```

- `SoloAvisar`: en `true`, el vigilante avisa pero no detiene nada.
- `Permitidos`: textos que, si aparecen en la ruta o en la orden de un programa, hacen que el vigilante lo deje en paz.

Los cambios se toman la próxima vez que se enciende el vigilante.

## Cómo quitarlo

1. Abre `Velador.cmd`.
2. Opción 3 para apagar el vigilante y opción 4 para que ya no arranque con Windows.
3. Opción 7 para quitar el blindaje, si lo aplicaste.
4. Si mandaste algo a cuarentena y lo quieres de vuelta, opción 6.
5. Borra la carpeta de Velador y también `%LOCALAPPDATA%\Velador` y `%ProgramData%\Velador`.

## Dónde guarda sus cosas

`%LOCALAPPDATA%\Velador`: el registro (`registro.log`), los informes, la cuarentena y la copia que arranca con Windows (`app`).
`%ProgramData%\Velador`: la copia de la configuración anterior del antivirus, para poder deshacer el blindaje.

No manda nada a internet: Velador no se conecta a ningún servidor.

## Pruebas

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File pruebas\probar.ps1
```

Corre 62 pruebas en una carpeta temporal con casos inofensivos. No toca la computadora ni pide administrador.

Si quieres revisar el código o proponer un cambio, la guía está en [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Nota para quien edite `velador.ps1`

Debe guardarse como UTF-8 **con BOM**. Sin esa marca, PowerShell 5.1 lee mal los acentos y el archivo puede no abrir.

Si el vigilante arranca con Windows, usa una copia guardada en `%LOCALAPPDATA%\Velador\app`. Después de editar,
quita y vuelve a poner el arranque (opción 4, dos veces) para que tome la versión nueva.

## Sin garantía

Velador es un proyecto nuevo y se ofrece tal cual, sin garantía de ningún tipo (licencia MIT, archivo `LICENSE`).
Si te da una falsa alarma o se le escapa algo, repórtalo para mejorarlo.
