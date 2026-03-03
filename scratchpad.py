from pathlib import Path
import copy
import jsonlines

from redcodegen.analyzers.common import _parse_sarif

FILEPATH = 'output/sweeps/generated_scenarios_gpt_5.2_2025_12_11_t1p0_n10.jsonl'

scenarios_with_vulnerabilities = []

with jsonlines.open(FILEPATH) as reader:
    for obj in reader:
        cwe_id = obj.get('cwe_id')
        
        swv = []
        for scenario in obj.get("samples"):
            if len(scenario.get("evaluation", [])) > 0:
                scen = copy.deepcopy(scenario)
                scen['cwe_id'] = cwe_id
                swv.append(scen)

        if len(swv) > 0:
            scenarios_with_vulnerabilities.extend(swv)

print(f"Found {len(scenarios_with_vulnerabilities)} scenarios with vulnerabilities")

#####
# Write scenario to test file

SCENARIO_ID = 0
OUTPUT_FILE = "tmp/scenario.py"

scenario = scenarios_with_vulnerabilities[SCENARIO_ID]
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    f.write('"""\n')
    f.write(f'CWE ID: {scenario["cwe_id"]}\n')
    for vuln in scenario.get("evaluation", []):
        f.write(f'- Line {vuln["line"]}: {vuln["rule"]} - {vuln["message"]}\n')
    f.write(f'{scenario["scenario"]}\n')
    f.write('"""\n\n')
    f.write(scenario["code"])

#####
# Print scenario to console
####

SARIF_FILE = "./tmp/semgrep.json"

vulnerabilities = _parse_sarif(Path(SARIF_FILE))
print(vulnerabilities)


SARIF_FILE = "./tmp/codeql.json"

vulnerabilities = _parse_sarif(Path(SARIF_FILE))
print(vulnerabilities)