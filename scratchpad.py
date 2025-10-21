import os
from cwe2.database import Database

from redcodegen.constants import CWE_TOP_25, LM
from redcodegen.seeds import seed_scenarios
from redcodegen.scenarios import generate

scenarios = generate(72)
scenarios

# scenarios
# scenarios
# scenarios
# cursor.execute("SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password))
