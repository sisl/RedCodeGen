from cwe2.database import Database
from redcodegen.constants import CWE_TOP_25

import dspy

from dotenv import load_dotenv
load_dotenv()

dspy.configure(lm=dspy.LM("openai/gpt-4o-mini", api_key=os.environ["OPENAI_API_KEY"]))
dspy.configure_cache(
    enable_disk_cache=False,
    enable_memory_cache=True,
)

db = Database()
entry = db.get(79)


vars(entry).keys()


