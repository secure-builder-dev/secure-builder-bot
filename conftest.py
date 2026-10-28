"""Every module's package (<module>/securebuilderbot_<module>/) on the path for every module's tests,
so a new module adds nothing here: pytest.ini's testpaths glob finds its tests and this finds its code."""

import sys
from pathlib import Path

for pkg in sorted(Path(__file__).resolve().parent.glob("*/securebuilderbot_*/")):
    d = str(pkg.parent)
    if d not in sys.path:
        sys.path.insert(0, d)
