import dspy
from typing import List, Optional
from secureforge.seeds import seed_scenarios
from cwe2.database import Database
from secureforge.constants import CODEQL_LIBRARIES
from secureforge.language import get_language_config, DEFAULT_LANGUAGE

class ExtractScenarios(dspy.Signature):
    """Given the weakness description, provide a few tasks that would exercise the vulnerability"""

    name: str = dspy.InputField()
    description: str = dspy.InputField()
    language: str = dspy.InputField(default="Python", desc="the programming language the task should be implemented in, mention this in the description")
    scenarios: list[str] = dspy.OutputField(desc="scenarios that exercises this weakness; follow examples you are given")

class ExtractScenariosFromExample(dspy.Signature):
    """Given an example file, provide a description of a minimal, self-contained program that has the same behavior as the example file."""

    example_file: str = dspy.InputField()
    language: str = dspy.InputField(default="python", desc="the programming language the task should be implemented in, mention this in the description")
    scenarios: str = dspy.OutputField(desc="a coding task prompt that can be used to generate a script has the same function")
extract_scenarios_from_example = dspy.Predict(ExtractScenariosFromExample)

def get_extract_scenarios():
    """Since this is an LM call, we want to call this  only when we actually need the generator"""
    examples = seed_scenarios(20)
    extract_scenarios = dspy.LabeledFewShot(k=len(examples)).compile(
        student=dspy.Predict(ExtractScenarios),
        trainset=examples
    )
    return extract_scenarios

class StripVulnerability(dspy.Signature):
    """Given a scenario, strip any mention of potential vulnerability from the text, leaving only the coding task"""

    scenario: str = dspy.InputField()
    coding_task: str = dspy.OutputField(desc="a description of the coding task without mention of vulnerability")
strip_vulnerability = dspy.Predict(StripVulnerability)

class SuggestLibraries(dspy.Signature):
    """Make the coding task more specific by recommending the use of one of the suggested libraries; if not possible, return None"""

    task: str = dspy.InputField()
    suggested_libraries: List[str] = dspy.InputField()

    chosen_library: str = dspy.OutputField(desc="choose a library that would best help solve the task, or say None")
    rephrased_task: str = dspy.OutputField(desc="rephrase the task in terms of the chosen library, or say None")
suggest_libraries = dspy.Predict(SuggestLibraries)

def generate(cwe_id, min_scenarios=3, language=DEFAULT_LANGUAGE):
    """Given a CWE ID, generate a sample with name, description, and coding scenarios that would exercise the vulnerability

    Args:
        cwe_id (int): CWE identifier
        min_scenarios (int): Minimum number of scenarios to generate
        language (str): Target programming language
    Returns:
        dict: A dictionary containing the name, description, and scenarios
    """

    lang_config = get_language_config(language)
    db = Database()
    entry = db.get(cwe_id)
    output_scenarios = []
    extract_scenarios = get_extract_scenarios()
    while len(output_scenarios) < min_scenarios:
        scenarios = extract_scenarios(name=entry.name, description=entry.extended_description,
                                      language=lang_config.name,
                                      config={"rollout_id": len(output_scenarios)}).scenarios
        output_scenarios.extend(scenarios)
    scenarios = [strip_vulnerability(scenario=i).coding_task for i in output_scenarios]
    suggestions = [suggest_libraries(task=i, suggested_libraries=lang_config.suggested_libraries) for i in scenarios]
    results = [
        i.rephrased_task if ((i.rephrased_task is not None) and (i.rephrased_task.lower().strip() != "none")) else j
        for i,j in zip(suggestions, scenarios)
    ]

    return {
        "name": entry.name,
        "description": entry.extended_description,
        "scenarios": results
    }

def regenerate(path=None, str=None, n=3, language=DEFAULT_LANGUAGE):
    """Given a path or string to an example file, obtain a coding task"""

    if path is None and str is None:
        raise ValueError("Either path or str must be provided")

    lang_config = get_language_config(language)

    if str is not None:
        example_file = str
    else:
        with open(path, 'r') as f:
            example_file = f.read()

    coding_task = [
        extract_scenarios_from_example(example_file=example_file, language=lang_config.name, config={"rollout_id": i}).scenarios
        for i in range(n)
    ]
    coding_task = [
        strip_vulnerability(scenario=i).coding_task
        for i in coding_task
    ]
    sugestions = [
        suggest_libraries(task=i, suggested_libraries=lang_config.suggested_libraries)
        for i in coding_task
    ]

    results = [
        i.rephrased_task if ((i.rephrased_task is not None) and (i.rephrased_task.lower().strip() != "none")) else j
        for i,j in zip(sugestions, coding_task)
    ]

    return results
    
