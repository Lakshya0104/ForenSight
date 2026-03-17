from setuptools import setup, find_packages
import os

# Read requirements
def get_requirements():
    reqs = [
        "rich>=13.0.0",
        "flask>=2.0.0",
        "requests>=2.28.0",
        "python-dateutil>=2.8.0",
    ]
    req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(req_file):
        with open(req_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    reqs.append(line)
    return list(dict.fromkeys(reqs))  # deduplicate

setup(
    name="forensight",
    version="1.0.0",
    description="Linux Forensic Intelligence System — Offensive OS Detection, Anti-Forensic Analysis, MITRE ATT&CK Mapping",
    author="Team Cyber Nuggets",
    python_requires=">=3.8",

    # Include main.py at root + all src/ subpackages + dashboard/
    packages=["forensight"] + [
        "forensight." + p for p in find_packages(where="src")
    ],
    package_dir={
        "forensight": ".",
        **{
            "forensight." + p: os.path.join("src", *p.split("."))
            for p in find_packages(where="src")
        }
    },

    # Include non-Python files
    package_data={
        "forensight": [
            "dashboard/index.html",
            "tool_db.json",
        ],
    },
    include_package_data=True,

    install_requires=get_requirements(),

    # This creates the `forensight` command that calls main.py:run
    entry_points={
        "console_scripts": [
            "forensight=forensight.__main__:main",
        ],
    },
)