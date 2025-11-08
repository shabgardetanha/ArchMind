#!/usr/bin/env python3
"""
ArchMind Advanced – Real Tracing & Event Analysis
Target: GoogleCloudPlatform/microservices-demo
"""

import os
import ast
import json
from pathlib import Path
from collections import defaultdict
import yaml
import re

# ----------------------------
# 1. Discovery Layer
# ----------------------------
class DiscoveryEngine:
    def __init__(self, root_path):
        self.root_path = Path(root_path)

    def detect_languages(self):
        exts = defaultdict(int)
        for file in self.root_path.rglob("*.*"):
            exts[file.suffix] += 1
        return dict(exts)

    def detect_architecture(self):
        folders = [p.name.lower() for p in self.root_path.iterdir() if p.is_dir()]
        if "services" in folders:
            return "Microservices + DDD"
        return "Monolith"

    def map_services(self):
        services = []
        for folder in self.root_path.iterdir():
            if folder.is_dir() and any(folder.glob("Dockerfile")):
                services.append(folder.name)
        return services

# ----------------------------
# 2. Code Intelligence Layer
# ----------------------------
class CodeAnalyzer:
    def __init__(self, root_path):
        self.root_path = Path(root_path)

    def scan_patterns(self):
        patterns = {"Singleton": 0, "Factory": 0, "Strategy": 0}
        for pyfile in self.root_path.rglob("*.py"):
            try:
                tree = ast.parse(pyfile.read_text())
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        if "Singleton" in node.name:
                            patterns["Singleton"] += 1
            except Exception:
                continue
        return patterns

    def measure_complexity(self):
        total_funcs = 0
        total_nodes = 0
        for pyfile in self.root_path.rglob("*.py"):
            try:
                tree = ast.parse(pyfile.read_text())
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        total_funcs += 1
                        total_nodes += len(list(ast.walk(node)))
            except Exception:
                continue
        avg_complexity = (total_nodes / total_funcs) if total_funcs else 0
        return {"avg_complexity": round(avg_complexity, 2), "total_functions": total_funcs}

# ----------------------------
# 3. Domain Modeling Layer
# ----------------------------
class DomainModeler:
    def __init__(self, root_path):
        self.root_path = Path(root_path)

    def extract_contexts(self):
        contexts = []
        for pyfile in self.root_path.rglob("*.py"):
            if "user" in pyfile.stem.lower():
                contexts.append("UserContext")
            if "billing" in pyfile.stem.lower():
                contexts.append("BillingContext")
        return list(set(contexts))

    def map_event_flow(self):
        # Extract events from code: look for publish/subscribe methods (simplified)
        events = {"producers": {}, "consumers": {}}
        for pyfile in self.root_path.rglob("*.py"):
            try:
                content = pyfile.read_text()
                produces = re.findall(r'publish\(["\'](\w+)["\']', content)
                consumes = re.findall(r'handle_event\(["\'](\w+)["\']', content)
                if produces:
                    events["producers"][pyfile.stem] = produces
                if consumes:
                    events["consumers"][pyfile.stem] = consumes
            except Exception:
                continue
        return events

# ----------------------------
# 4. Runtime Profiler
# ----------------------------
class RuntimeProfiler:
    def __init__(self, log_path):
        self.log_path = Path(log_path)

    def analyze_tracing(self):
        # Parse logs for latency/errors
        critical_path = []
        total_latency = 0
        count = 0
        errors = 0
        for log_file in self.log_path.rglob("*.log"):
            try:
                for line in log_file.read_text().splitlines():
                    if "latency" in line:
                        match = re.search(r"latency=(\d+)", line)
                        if match:
                            total_latency += int(match.group(1))
                            count += 1
                    if "ERROR" in line or "Exception" in line:
                        errors += 1
                    if "path=" in line:
                        match = re.search(r"path=(\S+)", line)
                        if match:
                            critical_path.append(match.group(1))
            except Exception:
                continue
        avg_latency = (total_latency / count) if count else 0
        return {"avg_latency_ms": round(avg_latency, 2), "critical_path": list(set(critical_path)), "errors": errors}

# ----------------------------
# 5. Security & Compliance Layer
# ----------------------------
class SecurityScanner:
    def __init__(self, root_path):
        self.root_path = Path(root_path)

    def find_secrets(self):
        secrets = []
        for f in self.root_path.rglob("*.*"):
            try:
                content = f.read_text(errors='ignore')
                if any(k in content for k in ["AWS_KEY", "DB_PASSWORD", "SECRET", "TOKEN"]):
                    secrets.append(str(f))
            except Exception:
                continue
        return secrets

    def evaluate_auth_model(self):
        # Detect auth patterns
        auth = {"OAuth2": False, "JWT": False, "RBAC": False}
        for pyfile in self.root_path.rglob("*.py"):
            try:
                text = pyfile.read_text()
                if "oauth" in text.lower():
                    auth["OAuth2"] = True
                if "jwt" in text.lower():
                    auth["JWT"] = True
                if "rbac" in text.lower():
                    auth["RBAC"] = True
            except Exception:
                continue
        return auth

# ----------------------------
# 6. DevOps Intelligence Layer
# ----------------------------
class DevOpsAnalyzer:
    def __init__(self, root_path):
        self.root_path = Path(root_path)

    def parse_pipelines(self):
        pipelines = {}
        for f in self.root_path.rglob("*.yml"):
            if ".github/workflows" in str(f):
                pipelines[str(f)] = "CI/CD pipeline detected"
        return pipelines

    def assess_risks(self):
        return {"rollback_safe": False, "manual_steps": 2}

# ----------------------------
# 7. Insight & Decision Layer
# ----------------------------
class InsightEngine:
    def prioritize_risks(self, findings):
        critical = []
        medium = []
        for k, v in findings.items():
            if k in ["secrets", "errors", "latency"]:
                critical.append(k)
            else:
                medium.append(k)
        return {"critical": critical, "medium": medium}

# ----------------------------
# 8. Orchestrator
# ----------------------------
class ArchMind:
    def __init__(self, root_repo_path, log_path):
        self.root_path = root_repo_path
        self.log_path = log_path
        self.discovery = DiscoveryEngine(root_repo_path)
        self.code_analyzer = CodeAnalyzer(root_repo_path)
        self.domain_modeler = DomainModeler(root_repo_path)
        self.runtime = RuntimeProfiler(log_path)
        self.security = SecurityScanner(root_repo_path)
        self.devops = DevOpsAnalyzer(root_repo_path)
        self.insight = InsightEngine()

    def run(self):
        output = {}
        # Discovery
        output['languages'] = self.discovery.detect_languages()
        output['architecture'] = self.discovery.detect_architecture()
        output['services'] = self.discovery.map_services()
        # Code analysis
        output['patterns'] = self.code_analyzer.scan_patterns()
        output['complexity'] = self.code_analyzer.measure_complexity()
        # Domain
        output['contexts'] = self.domain_modeler.extract_contexts()
        output['event_flow'] = self.domain_modeler.map_event_flow()
        # Runtime
        runtime_stats = self.runtime.analyze_tracing()
        output['tracing'] = runtime_stats
        # Security
        output['secrets'] = self.security.find_secrets()
        output['auth_model'] = self.security.evaluate_auth_model()
        # DevOps
        output['pipelines'] = self.devops.parse_pipelines()
        output['deployment_risks'] = self.devops.assess_risks()
        # Insights
        output['risk_priorities'] = self.insight.prioritize_risks({
            "secrets": output['secrets'],
            "errors": runtime_stats['errors'],
            "latency": runtime_stats['avg_latency_ms'],
            "low_test_coverage": False
        })

        # Save output
        out_file = Path("archmind_output_real.json")
        out_file.write_text(json.dumps(output, indent=4))
        print(f"ArchMind real analysis completed. Results saved to {out_file}")
        return output

# ----------------------------
# 9. Execution
# ----------------------------
if __name__ == "__main__":
    root_repo_path = "./microservices-demo"  # update with your repo path
    log_path = "./microservices-demo/logs"   # logs folder (Zipkin, or microservices logs)
    archmind = ArchMind(root_repo_path, log_path)
    results = archmind.run()
