import random
import uuid
import string
import random_utils


class HardwareFingerprint:
    """
    Hardware-related GUIDs and identifiers
    """
    def __init__(self):
        self.hw_profile_guid = f"{{{uuid.uuid4()}}}"
        self.performance_guid = f"{{{uuid.uuid4()}}}"
        self.machine_guid = str(uuid.uuid4())
        self.win_update_guid = str(uuid.uuid4())
        self.system_client_id = self.__random_system_client_id()

    def random_hw_profile_guid(self):
        return self.hw_profile_guid

    def random_performance_guid(self):
        return self.performance_guid

    def random_machine_guid(self):
        return self.machine_guid

    def random_win_update_guid(self):
        return self.win_update_guid

    def random_client_id_validation(self):
        return self.system_client_id

    @staticmethod
    def __random_id1():
        random_id1 = random.choices(string.digits + string.ascii_uppercase, k=19)
        return random_utils.disperse_string(random_id1)

    @staticmethod
    def __random_id2():
        return random.choices(range(1, 255), k=5)

    @staticmethod
    def __random_system_client_id():
        system_client_id = [0] * 0x08
        system_client_id[0x00:0x04] = [0x06, 0x02, 0x28, 0x01]
        system_client_id[0x04:0x07] = random.sample(range(1, 255), 3)
        system_client_id[0x07] = 0
        
        system_client_id.extend(HardwareFingerprint.__random_id1())
        system_client_id.extend([0, 6, 0])
        system_client_id.extend(HardwareFingerprint.__random_id2())
        system_client_id.extend(random_utils.disperse_string("None"))
        return system_client_id