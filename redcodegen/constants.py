import os
import dspy

from dotenv import load_dotenv
load_dotenv()

CWE_TOP_25 = [
    79, 787, 89, 352, 22, 125, 78,
    416, 862, 434, 94, 20, 77, 287,
    269, 502, 200, 863, 918, 119, 476,
    798, 190, 400, 306
]

def create_lm(model_name="openai/gpt-4o-mini", temperature=0.8, api_key=None):
    """Create a DSPy language model instance.

    Args:
        model_name: Model identifier (e.g., "openai/gpt-4o-mini")
        api_key: API key (defaults to OPENAI_API_KEY env var)

    Returns:
        dspy.LM instance
    """
    if api_key is None:
        api_key = os.environ.get("OPENAI_API_KEY")
    return dspy.LM(
        model_name,
        api_key=api_key,
        temperature=temperature,
        max_tokens=16000
    )

SCENARIO_EXAMPLES = [
    dspy.Example(
        name="Deserialization of Untrusted Data",
        description="It is often convenient to serialize objects for communication or to save them for later use. However, deserialized data or code can often be modified without using the provided accessor functions if it does not use cryptography to protect itself. Furthermore, any cryptography would still be client-side security -- which is a dangerous security assumption. Data that is untrusted can not be trusted to be well-formed. When developers place no restrictions on gadget chains, or series of instances and method invocations that can self-execute during the deserialization process (i.e., before the object is returned to the caller), it is sometimes possible for attackers to leverage them to perform unauthorized actions, like generating a shell.",
        scenarios=[
        ]
    )
]

CODEQL_LIBRARIES = [
    "Aioch", "Aiofile", "Aiofiles", "Aiohttp", "Aiomysql", "Aiopg", "Aiosqlite",
    "Airspeed", "Anyio", "Asyncpg", "Asyncpg", "BSon", "Baize", "Bottle",
    "CassandraDriver", "Chameleon", "Cherrypy", "Chevron", "ClickhouseDriver", "Cryptodome",
    "Cryptography", "Cx_Oracle", "Dill", "Django", "Fabric", "FastApi", "Flask",
    "FlaskAdmin", "FlaskSqlAlchemy", "Genshi", "Gradio", "Hdbcli", "Httpx",
    "Idna", "Invoke", "Jinja2", "Jmespath", "Joblib", "JsonPickle", "Ldap",
    "Ldap3", "Libtaxii", "Libxml2", "Lxml", "Mako", "MarkupSafe",
    "Multidict", "MySQLdb", "Mysql", "Numpy", "Opml", "Oracledb", "PEP249", "Pandas",
    "Paramiko", "Peewee", "Pexpect", "Phoenixdb", "Psycopg", "Psycopg2", "PyMongo",
    "PyMySQL", "Pycurl", "Pydantic", "Pymssql", "Pyodbc", "Pyramid", "Requests", "RestFramework",
    "Rsa", "RuamelYaml", "Sanic", "ServerLess", "Setuptools", "Simplejson", "SqlAlchemy",
    "Starlette", "Stdlib", "Stdlib", "Streamlit", "TRender", "Toml", "Torch", "Tornado",
    "Twisted", "Ujson", "Urllib3", "Werkzeug", "Xmltodict", "Yaml", "Yarl"
]
