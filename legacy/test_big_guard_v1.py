"""Original v1.1 prototype test, preserved. Run from the legacy/ folder: python -m pytest test_big_guard_v1.py"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from big_guard_v1 import EventDetector


def test_sleeper_demo_alert():
    detector = EventDetector()
    event = {
        "event_id": "test001", "timestamp": "2026-11-05T10:00:00+00:00",
        "user": "dormant_user", "process": "powershell", "resource": "finance_vault",
        "source": "TEST", "note": "test",
    }
    alert = detector.process(event)
    assert alert is not None
    assert alert["risk_score"] >= 70
    assert alert["severity"] == "HIGH"
