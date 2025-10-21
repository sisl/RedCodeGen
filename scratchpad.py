from redcodegen.constants import CWE_TOP_25, LM
from redcodegen.generator import run_cwe
from redcodegen.validator import evaluate

from cwe2.database import Database

CWES_OF_INTEREST = [35, 36] # or CWE_TOP_25
MIN_SAMPLES = 3

results = run_cwe(35, min_scenarios=MIN_SAMPLES)
evaluations = [evaluate(i) for i in results]

# save evaluations w/ CWE metadata  
# db = Database()
# entry = db.get(cwe_id)
# name=entry.name, description=entry.extended_description
# as well as run parameters such as the current dspy environment state



