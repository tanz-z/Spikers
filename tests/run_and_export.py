import json
import time
from datetime import datetime
import pytest

class DashboardResultsCollector:
    def __init__(self):
        self.results = []
        self.start_time = time.time()

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            self.results.append({
                "test_name": report.nodeid.split("::")[-1],
                "file": str(report.fspath),
                "status": "PASSED" if report.passed else ("FAILED" if report.failed else "SKIPPED"),
                "duration_ms": round(report.duration * 1000, 2),
                "error": str(report.longrepr) if report.failed else None
            })

    def pytest_sessionfinish(self, session, exitstatus):
        total_time = round((time.time() - self.start_time) * 1000, 2)
        total = len(self.results)
        passed = sum(1 for r in self.results if r["status"] == "PASSED")
        failed = sum(1 for r in self.results if r["status"] == "FAILED")

        summary = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "accuracy": round((passed / total * 100), 1) if total > 0 else 0,
            "total_duration_ms": total_time,
            "tests": self.results
        }

        with open("test_results.json", "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\n[+] Results saved to test_results.json ({passed}/{total} passed)")

if __name__ == "__main__":
    collector = DashboardResultsCollector()
    pytest.main(["tests/", "-v"], plugins=[collector])