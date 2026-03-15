import os
from pathlib import Path
import copy
import jsonlines
import dspy
import dotenv
dotenv.load_dotenv()

lm = dspy.LM(
    "openai/gpt-5.3-codex",
    temperature=1.0,
    max_tokens=16000,
    api_key=os.getenv("OPENAI_API_KEY")
)
dspy.configure(lm=lm)

with jsonlines.open("./data/generated_scenarios_gpt_5.3_codex_t1p0_n3_k3.jsonl") as f:
    data = [i for i in f][1:]
scenarios = sum([i["scenarios"] for i in data], [])

from redcodegen.generator.prompting import GenerateCode
coder = dspy.ChainOfThought(GenerateCode)

from dspy.teleprompt.gepa.gepa import GEPAFeedbackMetric, GEPA
from dspy.teleprompt.gepa.gepa_utils import ScoreWithFeedback

from redcodegen.language import DEFAULT_LANGUAGE
from redcodegen.analyzers.common import AnalysisTool
from redcodegen.analyzers.evaluate import evaluate

class AnalyzerFusedFeedback(GEPAFeedbackMetric):
    def __init__(self, tool: AnalysisTool, language: DEFAULT_LANGUAGE):
        self.tool = tool
        self.language = language
        
    def __call__(self, gold, pred, trace=None, pred_name=None, pred_trace=None):
        res:List[Dict[str, Any]] = evaluate(pred.code, analysis_tool=self.tool, language=self.language)
        vuln_str = "\n".join([
            f'- Line {vuln["line"]}: {vuln["rule"]} - {vuln["message"]}' for vuln in res
        ])

        if len(res) > 0:
            return ScoreWithFeedback(score=-1, feedback=f"The generated trace contains vulnerabilities. Please fix the code to remove all vulnerabilities. {vuln_str}") 
        else:
            return ScoreWithFeedback(score=1, feedback="The generated trace does not contain any vulnerabilities. Good job!")


examples = []
for i in scenarios:
    scenario = i["scenario"]
    test = i["tests"]
    for r in i["rollouts"]:
        if len(r["vulnerabilities"]) > 0:
            code = r["code"]
            examples.append(
                dspy.Example(
                    task=scenario,
                    language=DEFAULT_LANGUAGE,
                    test_code=test,
                    code=code
                ).with_inputs("task", "language", "test_code")
            )

gepa = GEPA(
    metric=AnalyzerFusedFeedback(AnalysisTool.CODEQL, DEFAULT_LANGUAGE),
    auto="light",
    reflection_lm=dspy.LM(model='gpt-5', temperature=1.0, max_tokens=32000)
)
prog = gepa.compile(coder, trainset=examples)
prog.save("./output/tuned.json")

dspy.load("./output/tuned.json")

from dspy import BaseModule
coder.load("./output/tuned.json")
coder










# data[0]

# data[0].keys()
# sum([i["samples"] for i in data], [])[0]


# from redcodegen.analyzers.common import _parse_sarif

# FILEPATH = 'output/sweeps/generated_scenarios_gpt_5.2_2025_12_11_t1p0_n10.jsonl'

# scenarios_with_vulnerabilities = []

# with jsonlines.open(FILEPATH) as reader:
#     for obj in reader:
#         cwe_id = obj.get('cwe_id')
        
#         swv = []
#         for scenario in obj.get("samples"):
#             1+1
#             if len(scenario.get("evaluation", [])) > 0:
#                 scen = copy.deepcopy(scenario)
#                 scen['cwe_id'] = cwe_id
#                 swv.append(scen)

#         if len(swv) > 0:
#             scenarios_with_vulnerabilities.extend(swv)

# print(f"Found {len(scenarios_with_vulnerabilities)} scenarios with vulnerabilities")

# #####
# # Write scenario to test file

# SCENARIO_ID = 0
# OUTPUT_FILE = "tmp/scenario.py"

# scenario = scenarios_with_vulnerabilities[SCENARIO_ID]
# with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
#     f.write('"""\n')
#     f.write(f'CWE ID: {scenario["cwe_id"]}\n')
#     for vuln in scenario.get("evaluation", []):
#         f.write(f'- Line {vuln["line"]}: {vuln["rule"]} - {vuln["message"]}\n')
#     f.write(f'{scenario["scenario"]}\n')
#     f.write('"""\n\n')
#     f.write(scenario["code"])

# #####
# # Print scenario to console
# ####

# SARIF_FILE = "./tmp/semgrep.json"

# vulnerabilities = _parse_sarif(Path(SARIF_FILE))
# print(vulnerabilities)


# SARIF_FILE = "./tmp/codeql.json"

# vulnerabilities = _parse_sarif(Path(SARIF_FILE))
# print(vulnerabilities)

