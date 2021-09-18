import yaml
from case import base
from sys import argv
from config import Configure

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

MANAGER_VERSION = "0.0.1"

class SanityManager:
    def __init__(self, test_case_file):
        self._config = Configure(yaml.load(open(test_case_file, "r"), Loader=Loader))
        try:
            self._config.check()
        except RuntimeError as e:
            raise RuntimeError("failed to parse test case") from e

    def run(self):
        stub1, stub2 = None, None
        try:
            stub1 = self._config.connect_side1()
            stub2 = self._config.connect_side2()
        except RuntimeError as e:
            raise RuntimeError("failed to connect") from e

        cases = self._config.cases()
        if not cases:
            raise RuntimeError("missing test_cases setting")

        test = base.TestCase(stub1, stub2, self._config.side1(), self._config.side2())
        for c in cases:
            test.run(c)


if __name__ == "__main__":
    test_file = argv[1]
    manager = SanityManager(test_file)
    manager.run()
