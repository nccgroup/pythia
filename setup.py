import setuptools
from pythia import VERSION_STRING

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pythia",
    version=VERSION_STRING,
    author="David Cannings",
    author_email="david@edeca.net",
    description="Extract class information from compiled Delphi binaries",
    license="GNU Affero General Public License v3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nccgroup/pythia",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': ['pythia=pythia.app:main'],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Environment :: Win32 (MS Windows)",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
    ],
    install_requires=[
        'construct',
        'pefile',
        'PyYAML',
        'treelib',
        'prettytable',
    ],
)