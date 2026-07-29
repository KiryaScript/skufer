import uuid


class TelemetryFingerprint:
    """
    Windows telemetry IDs generator
    """
    def __init__(self):
        self.device_id_guid = str(uuid.uuid4()).upper()

    def random_device_id_guid(self):
        return self.device_id_guid