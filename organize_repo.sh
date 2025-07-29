#!/bin/bash

# Create target directories
mkdir -p subspyder configs wordlists examples docs tests

# Move code files
mv subspyder_cli.py subspyder/cli.py 2>/dev/null
mv setup.py . 2>/dev/null

# Move configuration files
mv subspyder_config.ini configs/ 2>/dev/null
mv subspyder_config_template.ini configs/ 2>/dev/null

# Move wordlists
mv wordlist.txt wordlists/ 2>/dev/null

# Move example usage
mv example_usage.py examples/ 2>/dev/null

# Move documentation
mv SETUP_GUIDE.md PROJECT_STRUCTURE.md GITHUB_README.md CONTRIBUTING.md docs/ 2>/dev/null

# Ensure __init__.py exists for Python package
touch subspyder/__init__.py

echo "✅ Repo reorganized professionally."
#!/bin/bash

# Create target directories
mkdir -p subspyder configs wordlists examples docs tests

# Move code files
mv subspyder_cli.py subspyder/cli.py 2>/dev/null
mv setup.py . 2>/dev/null

# Move configuration files
mv subspyder_config.ini configs/ 2>/dev/null
mv subspyder_config_template.ini configs/ 2>/dev/null

# Move wordlists
mv wordlist.txt wordlists/ 2>/dev/null

# Move example usage
mv example_usage.py examples/ 2>/dev/null

# Move documentation
mv SETUP_GUIDE.md PROJECT_STRUCTURE.md GITHUB_README.md CONTRIBUTING.md docs/ 2>/dev/null

# Ensure __init__.py exists for Python package
touch subspyder/__init__.py

echo "✅ Repo reorganized professionally."
