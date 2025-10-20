import dspy
import jsonlines
import os
import re
from pathlib import Path
from cwe2.database import Database

from redcodegen.constants import LM
dspy.configure(lm=LM)

class DescribeScenario(dspy.Signature):
    """given a code snippet, describe what scenario/situation the code is trying to accomplish"""

    code: str = dspy.InputField()
    language: str = dspy.InputField()
    scenario: str = dspy.OutputField(desc="a brief description of what this code snippet is trying to do")


def seed_scenarios(k=None) -> list[dspy.Example]:
    """Parse scenario_dow.jsonl and create dspy.Example objects for ExtractScenarios"""

    # Get the path to the JSONL file relative to this file
    data_path = Path(__file__).parent / "data" / "scenario_dow.jsonl"

    # Initialize CWE database
    db = Database()

    # Group scenarios by CWE
    cwe_scenarios = {}

    with jsonlines.open(data_path) as reader:
        for indx, item in enumerate(reader):
            # Extract CWE number from scenario_id (e.g., "DoW/CWE-502-0" -> 502)
            if k is not None and indx >= k:
                break
            match = re.search(r'CWE-(\d+)', item['scenario_id'])
            if not match:
                continue

            cwe_id = int(match.group(1))

            if cwe_id not in cwe_scenarios:
                cwe_scenarios[cwe_id] = []

            # Generate scenario description from the prompt
            describe = dspy.ChainOfThought(DescribeScenario)
            result = describe(code=item['prompt'], language=item['language'])

            cwe_scenarios[cwe_id].append(result.scenario)

    # Create dspy.Example objects
    examples = []
    for cwe_id, scenarios in cwe_scenarios.items():
        try:
            cwe_entry = db.get(cwe_id)

            example = dspy.Example(
                name=cwe_entry.name,
                description=cwe_entry.extended_description or cwe_entry.description,
                scenarios=scenarios
            ).with_inputs("name", "description")

            examples.append(example)
        except Exception as e:
            print(f"Warning: Could not get CWE-{cwe_id} from database: {e}")
            continue

    return examples

