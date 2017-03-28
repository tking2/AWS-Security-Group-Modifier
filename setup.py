#!/usr/bin/env python

# Setup script for AWS Security Group Modifier

from setuptools import setup

setup(
    name="aws_security_group",
    description="An interactive tool to mess with AWS Security Groups",
    version="0.1.0",
    author="Tom King",
    url="https://github.com/tking2/AWS-Security-Group",
    packages=['aws_security_group'],
    install_requires=["boto3"],
    entry_points={
        'console_scripts': [
            'aws_security_group=aws_security_group.aws_security_group:main'
        ],
    },
)
