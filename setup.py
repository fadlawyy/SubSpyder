"""
Setup script for SubSpyder package
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="subspyder",
    version="2.0.0",
    author="SubSpyder Team",
    author_email="team@subspyder.com",
    description="Advanced Subdomain Enumeration Tool",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/subspyder/subspyder",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "subspyder=subspyder_cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "subspyder": ["*.txt", "*.ini"],
    },
    keywords="subdomain enumeration security reconnaissance pentesting",
    project_urls={
        "Bug Reports": "https://github.com/subspyder/subspyder/issues",
        "Source": "https://github.com/subspyder/subspyder",
        "Documentation": "https://github.com/subspyder/subspyder/blob/main/README.md",
    },
) 