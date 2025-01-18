import json

class CustomRulesLoader:
    def __init__(self, rules_path):
        try:
            with open(rules_path, "r") as f:
                self.rules = json.load(f)
        except Exception as e:
            raise Exception("Error loading custom rules: {}".format(str(e)))

    def get_rules(self):
        return self.rules