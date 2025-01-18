import json

class ThreatIntelligence:
    def __init__(self, intel_path):
        try:
            with open(intel_path, "r") as f:
                self.intel = json.load(f)
        except Exception as e:
            raise Exception("Error loading threat intelligence: {}".format(str(e)))

    def get_intel(self):
        return self.intel