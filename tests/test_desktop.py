import gc
import os

from PySide6.QtCore import QCoreApplication, QEvent

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import unittest

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from desktop.charts import Activity, PermissionMatrix
from desktop.design import Inspector, Table, initialize


class DesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        initialize(cls.app, "#22D3EE")

    def tearDown(self):
        for widget in QApplication.topLevelWidgets():
            widget.close()
            widget.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        QApplication.processEvents()
        gc.collect()

    def test_sorted_tables_keep_their_original_evidence(self):
        table = Table(["Name", "Status"], (1,))
        table.fill(
            [
                (["B", "complete"], {"id": "second"}, {1: "complete"}),
                (["A", "error"], {"id": "first"}, {1: "error"}),
            ]
        )
        table.sortItems(0, Qt.SortOrder.AscendingOrder)
        self.assertEqual(table.payload(0)["id"], "first")
        self.assertEqual(table.item(0, 1).data(Qt.ItemDataRole.UserRole + 1), "error")
        table.close()

    def test_matrix_distinguishes_policy_from_observation(self):
        config = {
            "identities": {"owner": {}, "other": {}},
            "cases": [
                {
                    "name": "read",
                    "method": "GET",
                    "path": "/objects/{id}",
                    "allow": ["owner"],
                    "deny": ["other"],
                }
            ],
        }
        matrix = PermissionMatrix()
        matrix.set_context(config, None, False)
        self.assertEqual(matrix.item(0, 1).data(Qt.ItemDataRole.UserRole + 1), "allowed")
        self.assertEqual(matrix.item(0, 2).data(Qt.ItemDataRole.UserRole + 1), "denied")
        matrix.set_context(config, None, True)
        self.assertEqual(matrix.item(0, 1).data(Qt.ItemDataRole.UserRole + 1), "pending")
        matrix.close()

    def test_activity_uses_actual_flow_start_times(self):
        activity = Activity("#8B5CF6")
        activity.set_report(
            {
                "first": "2026-10-28T00:00:00Z",
                "last": "2026-10-28T00:00:24Z",
                "flows": [
                    {"first": "2026-10-28T00:00:01Z"},
                    {"first": "2026-10-28T00:00:01Z"},
                    {"first": "2026-10-28T00:00:20Z"},
                ],
            }
        )
        self.assertEqual(sum(item[2] for item in activity.bins), 3)
        self.assertEqual(activity.bins[1][2], 2)
        activity.close()

    def test_inspector_does_not_interpret_evidence_as_markup(self):
        inspector = Inspector()
        inspector.display({"value": "<script>alert(1)</script>"})
        self.assertIn("<script>", inspector.content.toPlainText())
        inspector.close()


class TraceWindowTests(unittest.TestCase):
    def tearDown(self):
        for widget in QApplication.topLevelWidgets():
            widget.close()
            widget.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        QApplication.processEvents()
        gc.collect()

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_no_capture_creates_no_fake_metrics_or_chart_data(self):
        from desktop.app import TraceHound

        window = TraceHound()
        self.assertEqual(window.navigation.count(), 8)
        self.assertIsNone(window.report)
        self.assertEqual(window.protocol_bars.values, [])
        self.assertEqual(window.activity.bins, [])
        self.assertEqual(window.options["memory-mb"].value(), 32)
        window.close()

    def test_filters_keep_coverage_and_original_report(self):
        from desktop.app import TraceHound

        window = TraceHound()
        flow = {
            "id": "TCP test",
            "protocol": "TCP",
            "a": "192.0.2.1:1234",
            "b": "192.0.2.2:443",
            "packets": 2,
            "bytes": 25,
            "gaps": False,
            "first": "2026-10-28T00:00:00Z",
            "last": "2026-10-28T00:00:02Z",
        }
        report = {
            "tool": "TraceHound",
            "schema": 1,
            "complete": True,
            "first": flow["first"],
            "last": flow["last"],
            "coverage": {"packets": 2},
            "flows": [flow],
            "alerts": [],
        }
        window.render(report)
        window.flow_search.setText("missing")
        self.assertEqual(window.flow_table.rowCount(), 0)
        self.assertEqual(len(window.report["flows"]), 1)
        window.flow_search.clear()
        self.assertEqual(window.flow_table.rowCount(), 1)
        window.close()
