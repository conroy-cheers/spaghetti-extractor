"""Hand-defined cuts for the real cleanup tail consumer."""
import json
from pathlib import Path

BOUNDARY = json.loads((Path(__file__).parents[2]/'fixtures/metapad-cleanup-tail/boundary.json').read_text())
