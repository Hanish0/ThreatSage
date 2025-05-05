import os
import sys

def setup_project_path():
    """Add the project root directory to Python path for imports"""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)