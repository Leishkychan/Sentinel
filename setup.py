from setuptools import setup, find_packages

setup(
    name="sentinel",
    version="0.1.0",
    description="AI-Powered Vulnerability Intelligence Platform — Blue team first.",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "anthropic>=0.49.0",
        "flask>=3.1.0",
        "flask-cors>=5.0.0",
        "flask-limiter>=3.9.4",
        "python-dotenv>=1.1.0",
        "pydantic>=2.11.3",
        "requests>=2.32.3",
        "rich>=14.0.0",
        "bandit>=1.8.3",
        "pip-audit>=2.9.0",
    ],
    extras_require={
        "azure": ["azure-cosmos>=4.9.0"],
        "dev":   ["pytest>=8.3.5", "pytest-asyncio>=0.25.3"],
    },
    entry_points={
        "console_scripts": [
            "sentinel=sentinel.run_scan:main",
        ],
    },
)
