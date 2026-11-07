from big_guard_v1 import EventDetector, generate_event
import time

print("BIG-Guard simulated event monitor. Press Ctrl+C to stop.")
detector = EventDetector()
try:
    while True:
        event = generate_event()
        print(f'[EVENT] {event["user"]} -> {event["process"]} -> {event["resource"]}')
        alert = detector.process(event)
        if alert:
            print(f'[ALERT] {alert["severity"]} | {alert["rule"]} | '
                  f'{alert["risk_score"]}/100 | {alert["explanation"]}')
        time.sleep(1.5)
except KeyboardInterrupt:
    print("\\nMonitor stopped.")
