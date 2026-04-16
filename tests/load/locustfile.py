from locust import HttpUser, task, between
from locust.exception import RescheduleTask
import random

BASE_EMAIL = "loadtest@mycyber.com"
BASE_PASSWORD = "loadtest123"


class MyCyberUser(HttpUser):
    wait_time = between(1, 3)
    token = None
    headers = {}

    def on_start(self):
        """Login before running tasks."""
        response = self.client.post(
            "/api/v1/auth/login",
            data={
                "username": BASE_EMAIL,
                "password": BASE_PASSWORD,
            },
        )
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            self.headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        else:
            raise RescheduleTask()

    @task(5)
    def scan_text_clean(self):
        """Most common operation — scan clean text."""
        self.client.post(
            "/api/v1/scan/text",
            json={
                "text": "Hello this is a normal business message with no sensitive data",
                "context": "general",
            },
            headers=self.headers,
        )

    @task(3)
    def scan_text_pii(self):
        """Scan text with PII — heavier workload."""
        self.client.post(
            "/api/v1/scan/text",
            json={
                "text": (
                    f"Customer CNIC: "
                    f"421{random.randint(10, 99)}"
                    f"1-123456{random.randint(1, 9)}"
                    f"-{random.randint(1, 9)} "
                    f"email: test{random.randint(1, 100)}@example.com"
                ),
                "context": "general",
            },
            headers=self.headers,
        )

    @task(2)
    def get_scan_history(self):
        """Check scan history."""
        self.client.get(
            "/api/v1/scan/history?page=1&page_size=10",
            headers=self.headers,
        )

    @task(2)
    def get_stats(self):
        """Dashboard stats."""
        self.client.get(
            "/api/v1/scan/stats/summary",
            headers=self.headers,
        )

    @task(1)
    def check_alerts(self):
        """Check alerts."""
        self.client.get(
            "/api/v1/alerts",
            headers=self.headers,
        )

    @task(1)
    def health_check(self):
        """Lightweight health ping."""
        self.client.get("/health")


class HeavyScanUser(HttpUser):
    """Simulates enterprise customer scanning files."""

    wait_time = between(3, 8)
    weight = 1

    def on_start(self):
        response = self.client.post(
            "/api/v1/auth/login",
            data={
                "username": BASE_EMAIL,
                "password": BASE_PASSWORD,
            },
        )
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            self.headers = {
                "Authorization": f"Bearer {self.token}",
            }

    @task
    def scan_large_text(self):
        """Simulate large document scan."""
        large_text = (
            "This is a large document. " * 500
            + "CNIC: 42101-1234567-1 "
            + "email: sensitive@corp.com "
        )
        self.client.post(
            "/api/v1/scan/text",
            json={
                "text": large_text,
                "context": "document",
            },
            headers=self.headers,
        )
