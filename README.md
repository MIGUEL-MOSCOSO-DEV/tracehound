# TraceHound

Análisis forense offline de PCAP con reconstrucción TCP acotada y detecciones explicables.

[![CI](https://github.com/MIGUEL-MOSCOSO-DEV/tracehound/actions/workflows/ci.yml/badge.svg)](https://github.com/MIGUEL-MOSCOSO-DEV/tracehound/actions/workflows/ci.yml) · [Descargas](https://github.com/MIGUEL-MOSCOSO-DEV/tracehound/releases/latest) · [MIT](LICENSE)

![Interfaz de TraceHound](docs/overview.png)

## Qué incluye

- PCAP clásico Ethernet, raw IP y Linux cooked; IPv4/IPv6 y TCP/UDP.
- Reconstrucción TCP limitada por memoria, con registro de huecos y solapamientos.
- Metadatos DNS, HTTP y TLS ClientHello; cobertura y límites visibles.
- Alertas de barridos de puertos, periodicidad y anomalías DNS con explicaciones alternativas.

No captura tráfico en vivo, no descifra TLS y no admite PCAPNG directamente. Los flujos reutilizados se agrupan por extremos; no constituyen una reconstrucción completa de sesiones TCP.

## Windows

Descarga **TraceHound-windows-x64.zip**, extrae todo el contenido y abre **TraceHound/TraceHound.exe**. La carpeta `_internal` debe permanecer junto al ejecutable. No requiere Python ni instalación. Compatible con Windows 10/11 de 64 bits.

El ejecutable **tracehound-cli.exe** permite trabajar desde terminal. Ejecuta `--help` para consultar sus opciones. Los archivos SHA256SUMS permiten verificar las descargas.

La aplicación inicia sin proyectos, objetivos, credenciales ni datos precargados. Los planes e informes se guardan localmente, en las rutas que selecciones.

## Desarrollo

Requiere Python 3.11 o posterior y Go (consulta go.mod). Desde la raíz del repositorio:

```text
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
go build -o bin/tracehound-cli.exe ./cmd/tracehound
.venv\Scripts\python launch.py
```

Para generar la distribución en un entorno virtual limpio:

```text
.venv\Scripts\python tools/build_windows.py
```

El proceso compila la interfaz y el CLI, comprueba las dependencias nativas Qt, crea el ZIP y calcula sus hashes. Excluye la copia de ICU encontrada en PATH para que Qt utilice la API nativa de Windows. No copies DLL de otras instalaciones de Qt a `_internal`.

## Verificación

```text
python -m ruff check .
python -m ruff format --check .
python -m unittest discover -s tests -v
go vet ./...
go test ./...
```

La CI ejecuta las pruebas en Windows y Linux y genera el paquete Windows. Las pruebas usan recursos locales controlados; no auditan sistemas externos. La interfaz utiliza Qt/PySide6 y los motores funcionan de forma independiente.

## Uso responsable

Analiza únicamente capturas cuyo tratamiento tengas autorizado. Los informes pueden contener direcciones y nombres de sistemas. Conserva los informes como información sensible.

## Licencia

Código MIT. Las bibliotecas Qt se distribuyen de forma dinámica bajo su licencia correspondiente; consulta [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) y la carpeta [licenses](licenses).
