import yaml
import ipaddress
import grpc
from proto import side_pb2_grpc
from case import read_remote_success
from sys import argv

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

MANAGER_VERSION = '0.0.1'

CASE_MAPPING = {
    'read_remote_success': read_remote_success.ReadRemoteSuccess,
}

def check_ip_port(side, ip, port):
    if not ip or not port:
        raise RuntimeError('{} missing ip or port setting'.format(side,))

    try:
        ipaddress.ip_address(ip)
    except Exception:
        raise RuntimeError('{} ip address is not correct, value we get is: {}'.format(side, ip))


class SanityManager:
    def __init__(self, test_case_file):
        self.__case = yaml.load(open(test_case_file, 'r'), Loader=Loader)
        try:
            self.__check_case()
        except RuntimeError as e:
            raise RuntimeError('failed to parse test case') from e
        
    def __check_case(self):
        side_1 = self.__case.get('side_1')
        if not side_1:
            raise RuntimeError('missing side_1 definition')

        side_2 = self.__case.get('side_2')
        if not side_2:
            raise RuntimeError('missing side_2 definition')

        check_ip_port('side_1', side_1.get('ip'), side_1.get('port'))
        check_ip_port('side_2', side_2.get('ip'), side_2.get('port'))

    def __connect_sides(self, side_name):
        side = self.__case.get(side_name)
        chan = grpc.insecure_channel('{}:{}'.format(side.get('ip'), side.get('port')) )
        return side_pb2_grpc.SideStub(chan)

    def run(self):
        stub1, stub2 = None, None
        try:
            stub1 = self.__connect_sides('side_1')
            stub2 = self.__connect_sides('side_2')
        except RuntimeError as e:
            raise RuntimeError('failed to connect') from e

        cases = self.__case.get('test_cases')
        if not cases:
            raise RuntimeError('missing test_cases setting')

        for c in cases:
            if not c in CASE_MAPPING:
                raise RuntimeError('{} test is not defnined'.format(c))
            test = CASE_MAPPING[c](stub1, stub2)
            test.run()
            

if __name__ == "__main__":
    test_file = argv[1]
    manager = SanityManager(test_file)
    manager.run()