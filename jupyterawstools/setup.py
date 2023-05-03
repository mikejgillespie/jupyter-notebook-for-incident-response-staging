from setuptools import setup, find_packages

setup(
    name='jupyterawstools',
    version='0.1.0',
    packages=find_packages(include=['jupyterawstools', 'jupyterirtools.*']),
    install_requires=[
        'pyathena'
    ]
)