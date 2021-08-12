from config import Side
from proto.side_pb2_grpc import SideStub

class TestCase:
    def __init__(self, stub1: SideStub, stub2: SideStub, side1: Side, side2: Side):
        self.stub1 = stub1
        self.stub2 = stub2
        self.side1 = side1
        self.side2 = side2

    def run(self):
        pass