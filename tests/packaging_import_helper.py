"""Import build helpers without making packaging a Python runtime package."""
import importlib.util
from pathlib import Path


def load_packaging_module(name):
    spec = importlib.util.spec_from_file_location('protohunter_build_' + name, Path(__file__).resolve().parents[1] / 'packaging' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
