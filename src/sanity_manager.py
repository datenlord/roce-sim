import yaml
from case import read_success, send_rnr_retry, send_sucess, write_success
from sys import argv
from config import Configure

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

MANAGER_VERSION = '0.0.1'

CASE_MAPPING = {
    'read_success': read_success.ReadSuccess,
    'send_rnr_retry': send_rnr_retry.SendRnrRetry,
    'send_success': send_sucess.SendSuccess,
    'write_success': write_success.WriteSuccess,
}

class SanityManager:
    def __init__(self, test_case_file):
        self._config = Configure(yaml.load(open(test_case_file, 'r'), Loader=Loader))
        try:
            self._config.check()
        except RuntimeError as e:
            raise RuntimeError('failed to parse test case') from e

    def run(self):
        stub1, stub2 = None, None
        try:
            stub1 = self._config.connect_side1()
            stub2 = self._config.connect_side2()
        except RuntimeError as e:
            raise RuntimeError('failed to connect') from e

        cases = self._config.cases()
        if not cases:
            raise RuntimeError('missing test_cases setting')

        for c in cases:
            if not c in CASE_MAPPING:
                raise RuntimeError('{} test is not defnined'.format(c))
            test = CASE_MAPPING[c](stub1, stub2, self._config.side1(), self._config.side2())
            test.run()

if __name__ == "__main__":
    test_file = argv[1]
    manager = SanityManager(test_file)
    manager.run()