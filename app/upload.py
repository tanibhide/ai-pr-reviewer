"""
File upload handling.

WARNING: deliberately insecure test fixture for the security reviewer.
Do not use in real code.
"""

import os
import tarfile
import yaml


def save_file(folder, filename, data):
    path = os.path.join(folder, filename)
    with open(path, "wb") as f:
        f.write(data)
    return path


def load_config(text):
    return yaml.load(text)


def extract_archive(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest)


def make_temp_name(name):
    return "/tmp/" + name


def read_file(folder, name):
    with open(os.path.join(folder, name)) as f:
        return f.read()
