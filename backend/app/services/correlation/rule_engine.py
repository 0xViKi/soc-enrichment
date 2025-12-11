# backend/app/services/correlation/rule_engine.py
# Future extension (optional now)

class RuleEngine:
    def __init__(self):
        self.rules = []

    def register_rule(self, rule_func):
        self.rules.append(rule_func)

    def run(self, context):
        findings = []
        for rule in self.rules:
            r = rule(context)
            if r:
                findings.append(r)
        return findings


rule_engine = RuleEngine()
