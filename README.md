# PatrowlHears4py
Python API Client for PatrowlHears4py

# Deployment commands
rm -rf dist/ build/ PatrowlHears4py.egg-info
python setup.py sdist bdist_wheel
twine upload dist/*
