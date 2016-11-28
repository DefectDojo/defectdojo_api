#!/usr/bin/env python

import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from defect_dojo_api import __version__ as version

with open('README.rst', 'r') as f:
    readme = f.read()

# Publish helper
if sys.argv[-1] == 'build':
    os.system('python setup.py sdist bdist_wheel')
    sys.exit(0)

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist bdist_wheel upload -r pypi')
    sys.exit(0)

if sys.argv[-1] == 'publish-test':
    os.system('python setup.py sdist bdist_wheel upload -r pypitest')
    sys.exit(0)

setup(
    name='defectdojo_api',
    packages=['defectdojo_api'],
    version=version,
    description='An API wrapper to facilitate interactions with Defect Dojo.',
    long_description=readme,
    author='Aaron Weaver',
    author_email='aaron.weaver2@gmail.com',
    url='https://github.com/aaronweaver/defect_dojo_api',
    download_url='https://github.com/aaronweaver/defect_dojo_api/tarball/' + version,
    license='MIT',
    install_requires=['requests'],
    keywords=['dojo', 'api', 'security', 'software'],
    classifiers=[
        'Development Status :: 1 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ]
)
