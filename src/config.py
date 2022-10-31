from typing import Final
import ipaddress
import grpc
from proto import side_pb2_grpc


def check_ip_port(side, ip, port):
    if not ip or not port:
        raise RuntimeError(
            "{} missing ip or port setting".format(
                side,
            )
        )

    try:
        ipaddress.ip_address(ip)
    except Exception:
        raise RuntimeError(
            "{} ip address is not correct, value we get is: {}".format(side, ip)
        )


class Configure:
    SIDE1: Final = "side_1"
    SIDE2: Final = "side_2"
    IP: Final = "ip"
    PORT: Final = "port"
    CASES: Final = "test_cases"
    TEST_ALL: Final = "test_all"

    def __init__(self, case):
        self._inner = case

    def check(self):
        side_1 = self._inner.get(Configure.SIDE1)
        if not side_1:
            raise RuntimeError("missing side_1 definition")

        side_2 = self._inner.get(Configure.SIDE2)
        if not side_2:
            raise RuntimeError("missing side_2 definition")

        check_ip_port(
            Configure.SIDE1, side_1.get(Configure.IP), side_1.get(Configure.PORT)
        )
        check_ip_port(
            Configure.SIDE2, side_2.get(Configure.IP), side_2.get(Configure.PORT)
        )

    def connect_side1(self):
        return self._connect_sides(Configure.SIDE1)

    def connect_side2(self):
        return self._connect_sides(Configure.SIDE2)

    def cases(self):
        all = self._inner.get(Configure.TEST_ALL)
        if all:
            import os

            dir = "./case"
            cases = []
            for root, dirs, files in os.walk(dir):
                for file in files:
                    if file[-5:] == ".yaml":
                        cases.append(os.path.join(root, file))
            return cases
        else:
            return self._inner.get(Configure.CASES)

    def side1(self):
        return Side(self._inner.get(Configure.SIDE1))

    def side2(self):
        return Side(self._inner.get(Configure.SIDE2))

    def _connect_sides(self, side_name):
        side = self._inner.get(side_name)
        chan = grpc.insecure_channel(
            "{}:{}".format(side.get(Configure.IP), side.get(Configure.PORT))
        )
        return side_pb2_grpc.SideStub(chan)


class Side:
    DEV_NAME: Final = "dev_name"
    IB_PORT: Final = "ib_port"
    GID_IDX: Final = "gid_idx"
    IMM_FLAG: Final = "imm_flag"

    def __init__(self, side):
        self._inner = side

    def dev_name(self):
        return self._inner.get(Side.DEV_NAME)

    def ib_port(self):
        return self._inner.get(Side.IB_PORT)

    def gid_idx(self):
        return self._inner.get(Side.GID_IDX)

    def imm_flag(self):
        return self._inner.get(Side.IMM_FLAG)
