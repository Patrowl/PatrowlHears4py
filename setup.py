#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Setup file."""
from setuptools import setup, find_packages
import os
import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# # The text of the README file
# README = (HERE / "README.md").read_text()

# automatically captured required modules for install_requires in requirements.txt
with open(os.path.join(HERE, 'requirements.txt'), encoding='utf-8') as f:
    all_reqs = f.read().split('\n')

install_requires = [x.strip() for x in all_reqs if ('git+' not in x) and (
    not x.startswith('#')) and (not x.startswith('-'))]

dependency_links = [x.strip().replace('git+', '') for x in all_reqs if 'git+' not in x]

setup(
    name='PatrowlHears4py',
    version='1.2.0',
    description='Python API client and CLI for PatrowlHears',
    url='https://github.com/Patrowl/PatrowlHears4py',
    author='Nicolas Mattiocco',
    author_email='nicolas@patrowl.io',
    license='AGPLv3',
    packages=find_packages(),
    install_requires=install_requires,
    keyword="cve, vuln, vulnerabilities, security, nvd, exploit, poc",
    dependency_links=dependency_links,
    entry_points='''
        [console_scripts]
        hears=patrowlhears4py.cli:main
    ''',
    python_requires='>=3.6',
)
