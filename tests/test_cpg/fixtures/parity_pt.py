"""Cross-language path traversal fixture — Python."""

import os


def read_file():
    filename = os.environ.get("FILE_PATH")  # $ source=path_traversal
    with open(filename) as f:  # $ sink=path_traversal
        return f.read()


def serve_static():
    path = "/tmp/" + os.environ.get("USER_FILE", "")  # $ source=path_traversal
    return open(path).read()  # $ sink=path_traversal
