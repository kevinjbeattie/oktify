# setup.py

from setuptools import setup, find_packages

setup(
    name="oktify",
    version="0.1.0",
    description="Track Okta user role, group, and app changes over time.",
    author="Kevin J. Beattie",
    author_email="kevinjbeattie@gmail.com",
    url="https://github.com/kevinjbeattie/oktify",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-dotenv"
    ],
    entry_points={
        "console_scripts": [
            "oktify=run:main"
        ]
    },
    python_requires='>=3.8',
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Systems Administration"
    ],
    license="MIT",
)
