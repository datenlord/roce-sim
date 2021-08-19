from enum import IntEnum, IntFlag
from roce import opcode

DEFAULT_FLAG = 0

class QPS(IntEnum):
    RESET = 0
    INIT = 1
    RTR = 2
    RTS = 3
    SQD = 4
    SQE = 5
    ERR = 6
    UNKNOWN = 7

class PMTU(IntEnum):
    MTU_256 = 256
    MTU_512 = 512
    MTU_1024 = 1024
    MTU_2048 = 2048
    MTU_4096 = 4096

class WR_OPCODE(IntEnum):
    RDMA_WRITE = 0
    RDMA_WRITE_WITH_IMM = 1
    SEND = 2
    SEND_WITH_IMM = 3
    RDMA_READ = 4
    ATOMIC_CMP_AND_SWP = 5
    ATOMIC_FETCH_AND_ADD = 6
    LOCAL_INV = 7
    BIND_MW = 8
    SEND_WITH_INV = 9
    TSO = 10
    DRIVER1 = 11

    def send(op):
        return op in [WR_OPCODE.SEND, WR_OPCODE.SEND_WITH_IMM, WR_OPCODE.SEND_WITH_INV]

    def write(op):
        return op in [WR_OPCODE.RDMA_WRITE, WR_OPCODE.RDMA_WRITE_WITH_IMM]

    def atomic(op):
        return op in [WR_OPCODE.ATOMIC_CMP_AND_SWP, WR_OPCODE.ATOMIC_FETCH_AND_ADD]

class SEND_FLAGS(IntFlag):
    FENCE = 1
    SIGNALED = 2
    SOLICITED = 4
    INLINE = 8
    IP_CSUM = 16

class WC_STATUS(IntEnum):
    SUCCESS = 0
    LOC_LEN_ERR = 1
    LOC_QP_OP_ERR = 2
    LOC_EEC_OP_ERR = 3
    LOC_PROT_ERR = 4
    WR_FLUSH_ERR = 5
    MW_BIND_ERR = 6
    BAD_RESP_ERR = 7
    LOC_ACCESS_ERR = 8
    REM_INV_REQ_ERR = 9
    REM_ACCESS_ERR = 10
    REM_OP_ERR = 11
    RETRY_EXC_ERR = 12
    RNR_RETRY_EXC_ERR = 13
    LOC_RDD_VIOL_ERR = 14
    REM_INV_RD_REQ_ERR = 15
    REM_ABORT_ERR = 16
    INV_EECN_ERR = 17
    INV_EEC_STATE_ERR = 18
    FATAL_ERR = 19
    RESP_TIMEOUT_ERR = 20
    GENERAL_ERR = 21
    TM_ERR = 22
    TM_RNDV_INCOMPLETE = 23

    def from_nak(nak_val):
        # Nak value
        # 00000 PSN Sequence Error
        # 00001 Invalid Request
        # 00010 Remote Access Error
        # 00011 Remote Operational Error
        # 00100 Invalid RD Request
        # 00101 - 11111 reserved

        if nak_val == 1:
            return WC_STATUS.REM_INV_REQ_ERR
        elif nak_val == 2:
            return WC_STATUS.REM_ACCESS_ERR
        elif nak_val == 3:
            return WC_STATUS.REM_OP_ERR
        elif nak_val == 4:
            return WC_STATUS.REM_INV_RD_REQ_ERR
        else:
            raise Exception('unsupported NAK value for WC_STATUS')

class WC_FLAGS(IntFlag):
    GRH = 1
    WITH_IMM = 2
    IP_CSUM_OK = 4
    WITH_INV = 8
    TM_SYNC_REQ = 16
    TM_MATCH = 32
    TM_DATA_VALID = 64

class WC_OPCODE(IntEnum):
    SEND = 0
    RDMA_WRITE = 1
    RDMA_READ = 2
    COMP_SWAP = 3
    FETCH_ADD = 4
    BIND_MW = 5
    LOCAL_INV = 6
    TSO = 7
    RECV = 128
    RECV_RDMA_WITH_IMM = 129
    TM_ADD = 130
    TM_DEL = 131
    TM_SYNC = 132
    TM_RECV = 133
    TM_NO_TAG = 134
    DRIVER1 = 135

    def from_wr_op(wr_op):
        if wr_op in [WR_OPCODE.RDMA_WRITE, WR_OPCODE.RDMA_WRITE_WITH_IMM]:
            return WC_OPCODE.RDMA_WRITE
        elif wr_op in [WR_OPCODE.SEND, WR_OPCODE.SEND_WITH_IMM, WR_OPCODE.SEND_WITH_INV]:
            return WC_OPCODE.SEND
        elif wr_op == WR_OPCODE.RDMA_READ:
            return WC_OPCODE.RDMA_READ
        elif wr_op == WR_OPCODE.ATOMIC_CMP_AND_SWP:
            return WC_OPCODE.COMP_SWAP
        elif wr_op == WR_OPCODE.ATOMIC_FETCH_AND_ADD:
            return WC_OPCODE.FETCH_ADD
        elif wr_op == WR_OPCODE.LOCAL_INV:
            return WC_OPCODE.LOCAL_INV
        elif wr_op == WR_OPCODE.BIND_MW:
            return WC_OPCODE.BIND_MW
        elif wr_op == WR_OPCODE.TSO:
            return WC_OPCODE.TSO
        elif wr_op == WR_OPCODE.DRIVER1:
            return WC_OPCODE.DRIVER1
        else:
            raise Exception(f'WR_OPCODE={wr_op} has no WC_OPCODE')

    def from_rc_op(rc_op):
        if RC.send_last(rc_op) or RC.send_only(rc_op):
            return WC_OPCODE.SEND
        elif RC.write_last(rc_op) or RC.write_only(rc_op):
            if RC.has_imm(rc_op):
                return WC_OPCODE.RECV_RDMA_WITH_IMM
            else:
                return WC_OPCODE.RDMA_WRITE
        elif rc_op == RC.RDMA_READ_RESPONSE_LAST or rc_op == RC.RDMA_READ_RESPONSE_ONLY:
            return WC_OPCODE.RDMA_READ
        else:
            raise Exception(f'RC opcode={rc_op} has no WC_OPCODE')

class ACCESS_FLAGS(IntFlag):
    LOCAL_WRITE = 1
    REMOTE_WRITE = 2
    REMOTE_READ = 4
    REMOTE_ATOMIC = 8
    MW_BIND = 16
    ZERO_BASED = 32
    ON_DEMAND = 64
    HUGETLB = 128
    RELAXED_ORDERING = 1048576

class EVENT_TYPE(IntEnum):
    CQ_ERR = 0
    QP_FATAL = 1
    QP_REQ_ERR = 2
    QP_ACCESS_ERR = 3
    COMM_EST = 4
    SQ_DRAINED = 5
    PATH_MIG = 6
    PATH_MIG_ERR = 7
    DEVICE_FATAL = 8
    PORT_ACTIVE = 9
    PORT_ERR = 10
    LID_CHANGE = 11
    PKEY_CHANGE = 12
    SM_CHANGE = 13
    SRQ_ERR = 14
    SRQ_LIMIT_REACHED = 15
    QP_LAST_WQE_REACHED = 16
    CLIENT_REREGISTER = 17
    GID_CHANGE = 18
    WQ_FATAL = 19

class RC(IntEnum):
    SEND_FIRST = opcode('RC', 'SEND_FIRST')[0]
    SEND_MIDDLE = opcode('RC', 'SEND_MIDDLE')[0]
    SEND_LAST = opcode('RC', 'SEND_LAST')[0]
    SEND_LAST_WITH_IMMEDIATE = opcode('RC', 'SEND_LAST_WITH_IMMEDIATE')[0]
    SEND_ONLY = opcode('RC', 'SEND_ONLY')[0]
    SEND_ONLY_WITH_IMMEDIATE = opcode('RC', 'SEND_ONLY_WITH_IMMEDIATE')[0]
    RDMA_WRITE_FIRST = opcode('RC', 'RDMA_WRITE_FIRST')[0]
    RDMA_WRITE_MIDDLE = opcode('RC', 'RDMA_WRITE_MIDDLE')[0]
    RDMA_WRITE_LAST = opcode('RC', 'RDMA_WRITE_LAST')[0]
    RDMA_WRITE_LAST_WITH_IMMEDIATE = opcode('RC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE')[0]
    RDMA_WRITE_ONLY = opcode('RC', 'RDMA_WRITE_ONLY')[0]
    RDMA_WRITE_ONLY_WITH_IMMEDIATE = opcode('RC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE')[0]
    RDMA_READ_REQUEST = opcode('RC', 'RDMA_READ_REQUEST')[0]
    RDMA_READ_RESPONSE_FIRST = opcode('RC', 'RDMA_READ_RESPONSE_FIRST')[0]
    RDMA_READ_RESPONSE_MIDDLE = opcode('RC', 'RDMA_READ_RESPONSE_MIDDLE')[0]
    RDMA_READ_RESPONSE_LAST = opcode('RC', 'RDMA_READ_RESPONSE_LAST')[0]
    RDMA_READ_RESPONSE_ONLY = opcode('RC', 'RDMA_READ_RESPONSE_ONLY')[0]
    ACKNOWLEDGE = opcode('RC', 'ACKNOWLEDGE')[0]
    ATOMIC_ACKNOWLEDGE = opcode('RC', 'ATOMIC_ACKNOWLEDGE')[0]
    COMPARE_SWAP = opcode('RC', 'COMPARE_SWAP')[0]
    FETCH_ADD = opcode('RC', 'FETCH_ADD')[0]
    SEND_LAST_WITH_INVALIDATE = opcode('RC', 'SEND_LAST_WITH_INVALIDATE')[0]
    SEND_ONLY_WITH_INVALIDATE = opcode('RC', 'SEND_ONLY_WITH_INVALIDATE')[0]

    def send_last(op):
        return op in [
            RC.SEND_LAST,
            RC.SEND_LAST_WITH_IMMEDIATE,
            RC.SEND_LAST_WITH_INVALIDATE,
        ]

    def send_only(op):
        return op in [
            RC.SEND_ONLY,
            RC.SEND_ONLY_WITH_IMMEDIATE,
            RC.SEND_ONLY_WITH_INVALIDATE,
        ]

    def send(op):
        return op in [RC.SEND_FIRST, RC.SEND_MIDDLE] or RC.send_last(op) or RC.send_only(op)

    def write_last(op):
        return op in [
            RC.RDMA_WRITE_LAST,
            RC.RDMA_WRITE_LAST_WITH_IMMEDIATE,
        ]

    def write_only(op):
        return op in [
            RC.RDMA_WRITE_ONLY,
            RC.RDMA_WRITE_ONLY_WITH_IMMEDIATE,
        ]

    def write(op):
        return op in [RC.RDMA_WRITE_FIRST, RC.RDMA_WRITE_MIDDLE] or RC.write_last(op) or RC.write_only(op)

    def atomic(op):
        return op in [RC.COMPARE_SWAP, RC.FETCH_ADD]

    def read_resp(op):
        return op in [
            RC.RDMA_READ_RESPONSE_FIRST,
            RC.RDMA_READ_RESPONSE_MIDDLE,
            RC.RDMA_READ_RESPONSE_LAST,
            RC.RDMA_READ_RESPONSE_ONLY,
        ]

    def first_req_pkt(op):
        return op in [RC.SEND_FIRST, RC.RDMA_WRITE_FIRST]

    def mid_req_pkt(op):
        return op in [RC.SEND_MIDDLE, RC.RDMA_WRITE_MIDDLE]

    def last_req_pkt(op):
        return RC.send_last(op) or RC.write_last(op)

    def only_req_pkt(op):
        return RC.send_only(op) or RC.write_only(op)

    # def first_read_resp_pkt(op):
    #     return op in [RC.RDMA_READ_RESPONSE_FIRST]

    # def mid_read_resp_pkt(op):
    #     return op in [RC.RDMA_READ_RESPONSE_MIDDLE]

    # def last_read_resp_pkt(op):
    #     return op in [RC.RDMA_READ_RESPONSE_LAST]

    # def only_read_resp_pkt(op):
    #     return op in [RC.RDMA_READ_RESPONSE_ONLY]

    def request(op):
        return op in [
            RC.RDMA_READ_REQUEST,
            RC.COMPARE_SWAP,
            RC.FETCH_ADD,
        ] or RC.send(op) or RC.write(op)

    def response(op):
        return op in [
            RC.ACKNOWLEDGE,
            RC.ATOMIC_ACKNOWLEDGE,
        ] or RC.read_resp(op)

    def has_imm(op):
        return op in [
            RC.SEND_LAST_WITH_IMMEDIATE,
            RC.SEND_ONLY_WITH_IMMEDIATE,
            RC.RDMA_WRITE_LAST_WITH_IMMEDIATE,
            RC.RDMA_WRITE_ONLY_WITH_IMMEDIATE,
        ]

    def has_inv(op):
        return op in [RC.SEND_LAST_WITH_INVALIDATE, RC.SEND_ONLY_WITH_INVALIDATE]
