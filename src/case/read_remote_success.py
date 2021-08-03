from .base import TestCase
from proto import message_pb2, message_pb2_grpc

class ReadRemoteSuccess(TestCase):
    def __init__(self, stub1, stub2):
        TestCase.__init__(self, stub1, stub2)

    def run(self):
        request = message_pb2.OpenDeviceRequest(dev_name = 'dev1')
        response = self.stub1.OpenDevice(request)
        dev_id = response.dev_id
        print('get device id from response ', dev_id)