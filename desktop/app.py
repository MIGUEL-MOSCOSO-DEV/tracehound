import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QPlainTextEdit,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QWidget,
)

from .charts import Activity, Bars, timestamp
from .design import (
    Button,
    Card,
    Empty,
    Inspector,
    Metric,
    Search,
    Shell,
    Table,
    column,
    initialize,
    label,
    row,
)
from .reporting import read_report, write_html
from .runner import Runner

ACCENT = "#8B5CF6"


class TraceHound(Shell):
    def __init__(self):
        super().__init__("TraceHound", "Network Evidence Lab", ACCENT, "network")
        self.runner = Runner("tracehound")
        self.report = None
        self.time_filter = None
        self.pcap_path = None
        overview = self.add_page("Overview", "dashboard")
        captures = self.add_page("Capturas", "capture")
        flows = self.add_page("Flujos", "flows")
        protocols = self.add_page("Protocolos", "protocol")
        alerts = self.add_page("Alertas", "alert")
        evidence = self.add_page("Evidencias", "evidence")
        reports = self.add_page("Reportes", "report")
        settings = self.add_page("Ajustes", "settings")
        self.header_actions.addWidget(
            Button("Abrir reporte", self.open_report, "folder", ACCENT, quiet=True)
        )
        self.analyze_button = Button("Analizar captura", self.analyze, "play", ACCENT, True)
        self.header_actions.addWidget(self.analyze_button)
        metric_row = QHBoxLayout()
        self.metrics = []
        for title, glyph in [
            ("Paquetes leídos", "capture"),
            ("Flujos rastreados", "flows"),
            ("Payload observado", "protocol"),
            ("Alertas para revisar", "alert"),
        ]:
            metric = Metric(title, glyph, ACCENT)
            metric_row.addWidget(metric)
            self.metrics.append(metric)
        overview.addLayout(metric_row)
        self.overview_content = QStackedWidget()
        overview.addWidget(self.overview_content, 1)
        self.overview_content.addWidget(
            Empty(
                "La evidencia empieza en una captura",
                "Importa un PCAP clásico y reconstruye su contexto.\nEl análisis es offline: no captura tráfico ni realiza conexiones de red.",
                "capture",
                ACCENT,
                "Seleccionar captura",
                self.choose,
            )
        )
        dashboard = QWidget()
        dashboard_box = column(dashboard, 18)
        activity = Card(
            "Actividad observada",
            "Inicios de flujos por intervalo, en UTC. Selecciona una barra para filtrar el inventario.",
        )
        self.activity = Activity(ACCENT)
        self.activity.selected.connect(self.filter_interval)
        activity.box.addWidget(self.activity)
        dashboard_box.addWidget(activity)
        chart_row = QHBoxLayout()
        protocol_card = Card(
            "Distribución de protocolos", "Número de flujos rastreados, no tráfico descartado."
        )
        self.protocol_bars = Bars(ACCENT, "flujos")
        protocol_card.box.addWidget(self.protocol_bars)
        alert_card = Card("Alertas por severidad", "Patrones con evidencia, sujetos a revisión.")
        self.alert_bars = Bars("#A78BFA", "alertas")
        alert_card.box.addWidget(self.alert_bars)
        chart_row.addWidget(protocol_card)
        chart_row.addWidget(alert_card)
        dashboard_box.addLayout(chart_row)
        self.overview_content.addWidget(dashboard)
        import_card = Card(
            "Captura de trabajo",
            "Se procesa un archivo a la vez. No se modifica la captura original.",
        )
        self.capture_name = label("Ningún archivo seleccionado", "section")
        self.capture_meta = label("PCAP clásico / Ethernet, raw IP o Linux cooked", "muted", True)
        import_card.box.addWidget(self.capture_name)
        import_card.box.addWidget(self.capture_meta)
        import_card.box.addLayout(
            row(
                Button("Elegir PCAP", self.choose, "upload", ACCENT),
                Button("Abrir reporte existente", self.open_report, "folder", ACCENT, quiet=True),
                None,
            )
        )
        captures.addWidget(import_card)
        coverage = Card(
            "Cobertura y trazabilidad",
            "Las limitaciones forman parte del resultado, no se ocultan.",
        )
        self.coverage_text = QPlainTextEdit()
        self.coverage_text.setReadOnly(True)
        self.coverage_text.setPlaceholderText(
            "Aquí aparecerán huella SHA-256, tiempos, fragmentos, paquetes no soportados y límites de memoria alcanzados."
        )
        coverage.box.addWidget(self.coverage_text, 1)
        captures.addWidget(coverage, 1)
        toolbar = QHBoxLayout()
        self.flow_search = Search("Buscar IP, puerto o protocolo…")
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["Todos los protocolos", "TCP", "UDP"])
        toolbar.addWidget(self.flow_search, 1)
        toolbar.addWidget(self.protocol_filter)
        toolbar.addWidget(
            Button("Restablecer intervalo", self.clear_interval, "clock", ACCENT, quiet=True)
        )
        flows.addLayout(toolbar)
        self.interval_note = label("Sin filtro temporal", "muted")
        flows.addWidget(self.interval_note)
        split = QSplitter()
        self.flow_table = Table(
            ["Protocolo", "Extremo A", "Extremo B", "Paquetes", "Payload bytes", "Huecos"]
        )
        for col, width in [(0, 95), (1, 230), (2, 230), (3, 90), (4, 120)]:
            self.flow_table.setColumnWidth(col, width)
        self.flow_inspector = Inspector("Flujo reconstruido")
        split.addWidget(self.flow_table)
        split.addWidget(self.flow_inspector)
        split.setSizes([760, 340])
        self.flow_table.selected.connect(self.flow_inspector.display)
        flows.addWidget(split, 1)
        self.flow_search.textChanged.connect(self.filter_flows)
        self.protocol_filter.currentIndexChanged.connect(self.filter_flows)
        charts = QHBoxLayout()
        bytes_card = Card("Payload por protocolo", "Bytes observados, incluidas retransmisiones.")
        self.byte_bars = Bars(ACCENT, "bytes")
        bytes_card.box.addWidget(self.byte_bars)
        endpoint_card = Card(
            "Extremos con más tráfico",
            "Cada extremo acumula el payload de sus flujos. A/B no implica dirección de origen o destino.",
        )
        self.endpoint_bars = Bars("#22D3EE", "bytes")
        endpoint_card.box.addWidget(self.endpoint_bars)
        charts.addWidget(bytes_card)
        charts.addWidget(endpoint_card)
        protocols.addLayout(charts)
        self.protocol_table = Table(["Protocolo", "Flujos", "Paquetes rastreados", "Payload bytes"])
        protocols.addWidget(self.protocol_table, 1)
        alerts_toolbar = QHBoxLayout()
        self.alert_search = Search("Buscar regla, extremo o interpretación…")
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Todas las severidades", "warning", "info", "high"])
        alerts_toolbar.addWidget(self.alert_search, 1)
        alerts_toolbar.addWidget(self.severity_filter)
        alerts.addLayout(alerts_toolbar)
        self.alert_table = Table(["Severidad", "Regla", "Sujeto", "Interpretación"], (0,))
        self.alert_table.setColumnWidth(0, 140)
        self.alert_table.setColumnWidth(1, 235)
        self.alert_table.setColumnWidth(2, 250)
        self.alert_inspector = Inspector("Evidencia de la detección")
        alert_split = QSplitter()
        alert_split.addWidget(self.alert_table)
        alert_split.addWidget(self.alert_inspector)
        alert_split.setSizes([760, 340])
        alerts.addWidget(alert_split, 1)
        self.alert_table.selected.connect(self.select_alert)
        self.alert_search.textChanged.connect(self.filter_alerts)
        self.severity_filter.currentIndexChanged.connect(self.filter_alerts)
        evidence.addWidget(label("Evidencia seleccionada", "section"))
        evidence.addWidget(
            label(
                "Las alertas explican su base y sus límites. No constituyen un veredicto de malware.",
                "muted",
                True,
            )
        )
        self.evidence_inspector = Inspector("Detalle completo")
        evidence.addWidget(self.evidence_inspector, 1)
        exports = Card(
            "Reportes que se pueden revisar sin conexión",
            "JSON conserva resultados estructurados. HTML incluye evidencia y cobertura, sin recursos remotos.",
        )
        exports.box.addLayout(
            row(
                Button("Abrir reporte", self.open_report, "folder", ACCENT),
                Button("Exportar HTML", self.export, "download", ACCENT),
                None,
            )
        )
        reports.addWidget(exports)
        self.report_summary = QPlainTextEdit()
        self.report_summary.setReadOnly(True)
        self.report_summary.setPlaceholderText("No hay un reporte cargado.")
        reports.addWidget(self.report_summary, 1)
        budget = Card(
            "Presupuesto de análisis",
            "El presupuesto de payload no representa toda la memoria del proceso. Los límites alcanzados se registran en cobertura.",
        )
        self.options = {}
        limits = [
            ("max-flows", "Flujos máximos", 1, 20000, 2000),
            ("memory-mb", "Payload total / MB", 1, 512, 32),
            ("stream-kb", "Por dirección / KB", 1, 1024, 64),
            ("port-threshold", "Puertos distintos / 60 s", 5, 1000, 20),
        ]
        for key, title, minimum, maximum, default in limits:
            holder = QWidget()
            box = column(holder, 7)
            box.addWidget(label(title, "muted"))
            spin = QSpinBox()
            spin.setRange(minimum, maximum)
            spin.setValue(default)
            spin.setToolTip(title)
            box.addWidget(spin)
            self.options[key] = spin
            budget.box.addWidget(holder)
        settings.addWidget(budget)
        settings.addStretch()
        self.shortcut("Ctrl+O", self.choose)
        self.shortcut("Ctrl+Return", self.analyze)
        self.show_page("Overview")

    def choose(self):
        if self.busy:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar captura", "", "PCAP (*.pcap *.cap);;Todos los archivos (*)"
        )
        if path:
            self.pcap_path = Path(path)
            self.capture_name.setText(self.pcap_path.name)
            self.capture_meta.setText(
                str(self.pcap_path) + f" / {self.pcap_path.stat().st_size / 1024**2:.2f} MB"
            )
            self.workspace_label.setText(self.pcap_path.name)
            self.show_page("Capturas")
            self.notify("Captura seleccionada. Pulsa Analizar para procesarla.")

    def analyze(self):
        if self.busy:
            return
        if not self.pcap_path:
            self.choose()
            return
        folder = QFileDialog.getExistingDirectory(self, "Carpeta para el reporte")
        if not folder:
            return
        output = Path(folder) / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".report.json"
        )
        args = ["--pcap", self.pcap_path, "--out", output]
        for name, value in self.options.items():
            args.extend(["--" + name, str(value.value())])

        def operation(note):
            complete = self.runner.run(args, note)
            return (read_report(output) if output.exists() else None), complete

        self.task("Analizando captura offline…", operation, self.finished, self.runner.cancel)

    def finished(self, value):
        report, complete = value
        if report:
            self.render(report)
        self.show_page("Overview")
        self.notify(
            "Análisis finalizado. Revisa la cobertura antes de interpretar resultados."
            if complete
            else "Análisis parcial guardado."
        )

    def update_actions(self):
        self.analyze_button.setEnabled(not self.busy)

    def render(self, report):
        if report.get("tool") != "TraceHound":
            raise ValueError("El reporte pertenece a otra herramienta.")
        self.report = report
        self.time_filter = None
        coverage = report["coverage"]
        flows = report["flows"]
        payload = sum(flow["bytes"] for flow in flows)
        values = [
            coverage["packets"],
            len(flows),
            f"{payload / 1024:.1f} KB",
            len(report["alerts"]),
        ]
        for metric, value in zip(self.metrics, values):
            metric.set(value, "Reporte completo" if report["complete"] else "Cobertura parcial")
        self.overview_content.setCurrentIndex(1 if coverage["packets"] else 0)
        self.activity.set_report(report)
        counts = Counter(flow["protocol"] for flow in flows)
        self.protocol_bars.set_values(counts.most_common())
        self.alert_bars.set_values(
            Counter(alert["severity"] for alert in report["alerts"]).most_common()
        )
        bytes_by_protocol = Counter()
        packets_by_protocol = Counter()
        endpoints = Counter()
        for flow in flows:
            bytes_by_protocol[flow["protocol"]] += flow["bytes"]
            packets_by_protocol[flow["protocol"]] += flow["packets"]
            for value in [flow["a"], flow["b"]]:
                host = urlsplit("//" + value).hostname or value
                endpoints[host] += flow["bytes"]
        self.byte_bars.set_values(bytes_by_protocol.most_common())
        self.endpoint_bars.set_values(endpoints.most_common(8))
        self.protocol_table.fill(
            [
                (
                    [name, count, packets_by_protocol[name], bytes_by_protocol[name]],
                    {"protocol": name, "flows": count, "bytes": bytes_by_protocol[name]},
                    {},
                )
                for name, count in counts.items()
            ]
        )
        detail = {
            "capture_sha256": report.get("capture_sha256"),
            "first": report.get("first"),
            "last": report.get("last"),
            "coverage": coverage,
            "limits": report.get("options"),
        }
        self.coverage_text.setPlainText(json.dumps(detail, ensure_ascii=False, indent=2))
        self.report_summary.setPlainText(json.dumps(detail, ensure_ascii=False, indent=2))
        self.filter_flows()
        self.filter_alerts()

    def filter_interval(self, interval):
        self.time_filter = interval
        self.interval_note.setText(
            "Filtro UTC: "
            + " — ".join(
                datetime.fromtimestamp(value, timezone.utc).strftime("%H:%M:%S")
                for value in interval
            )
        )
        self.filter_flows()
        self.show_page("Flujos")

    def clear_interval(self):
        self.time_filter = None
        self.interval_note.setText("Sin filtro temporal")
        self.filter_flows()

    def filter_flows(self, *args):
        rows = []
        for flow in (self.report or {}).get("flows", []):
            if (
                self.flow_search.text().casefold()
                not in (flow["a"] + flow["b"] + flow["protocol"]).casefold()
            ):
                continue
            if (
                self.protocol_filter.currentIndex() > 0
                and flow["protocol"] != self.protocol_filter.currentText()
            ):
                continue
            if self.time_filter and (
                timestamp(flow["last"]) < self.time_filter[0]
                or timestamp(flow["first"]) > self.time_filter[1]
            ):
                continue
            rows.append(
                (
                    [
                        flow["protocol"],
                        flow["a"],
                        flow["b"],
                        flow["packets"],
                        flow["bytes"],
                        "Sí" if flow["gaps"] else "No",
                    ],
                    flow,
                    {},
                )
            )
        self.flow_table.fill(rows)

    def filter_alerts(self, *args):
        rows = []
        for alert in (self.report or {}).get("alerts", []):
            if (
                self.alert_search.text().casefold()
                not in json.dumps(alert, ensure_ascii=False).casefold()
            ):
                continue
            if (
                self.severity_filter.currentIndex() > 0
                and alert["severity"] != self.severity_filter.currentText()
            ):
                continue
            rows.append(
                (
                    [alert["severity"], alert["rule"], alert["subject"], alert["summary"]],
                    alert,
                    {0: alert["severity"]},
                )
            )
        self.alert_table.fill(rows)

    def select_alert(self, alert):
        self.alert_inspector.display(alert)
        self.evidence_inspector.display(alert)

    def open_report(self):
        path, _ = QFileDialog.getOpenFileName(self, "Abrir reporte", "", "JSON (*.json)")
        if path:
            try:
                self.render(read_report(path))
                self.workspace_label.setText(Path(path).stem)
                self.show_page("Overview")
                self.notify("Reporte local abierto. No se accedió a la captura original.")
            except (OSError, ValueError, TypeError, KeyError) as error:
                self.notify(str(error), True)

    def export(self):
        if not self.report:
            self.notify("Abre o genera un reporte antes de exportar.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar HTML local", "", "HTML (*.html)")
        if path:
            try:
                write_html(self.report, path)
                self.notify("Reporte HTML exportado sin recursos externos.")
            except OSError as error:
                self.notify(str(error), True)


def main():
    app = QApplication(sys.argv)
    initialize(app, ACCENT)
    window = TraceHound()
    window.show()
    sys.exit(app.exec())
