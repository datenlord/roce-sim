from enum import IntEnum

# A counter used to help implied nak retry hook to identify how many times it was entered
IMPLIED_NAK_SEQUENCE_RETRY_CNT = 0

# A counter used to help implied nak retry exceeded limit hook to identify how many times it was entered
IMPLIED_NAK_SEQUENCE_RETRY_EXCEEDED_CNT = 0


class HOOK_TYPE(IntEnum):
    SEND = 0
    RECV = 1
    RESP = 2


def sim_read_partial_retry_hook(wr_ssn, req_pkt, real_send):
    import roce

    if req_pkt[roce.BTH].psn == 4:
        req_pkt[roce.BTH].psn = 1
    return wr_ssn, req_pkt, real_send


def rxe_write_partial_retry_hook(wr_ssn, req_pkt, real_send):
    import roce

    if req_pkt[roce.BTH].psn == 1:
        return wr_ssn, req_pkt, False

    return wr_ssn, req_pkt, real_send


def sim_write_partial_retry_hook(resp_pkt, save_resp_pkt):
    import roce

    if resp_pkt[roce.BTH].psn == 3:
        resp_pkt[roce.BTH].psn = 1
        resp_pkt[roce.AETH].code = 3
        resp_pkt[roce.AETH].value = 0

    return resp_pkt, save_resp_pkt


def implied_nak_sequence_error_retry_hook(resp_pkt, save_resp_pkt):
    import roce

    global IMPLIED_NAK_SEQUENCE_RETRY_CNT

    if resp_pkt[roce.BTH].psn == 0:
        if IMPLIED_NAK_SEQUENCE_RETRY_CNT == 0:
            resp_pkt[roce.BTH].psn = 1
            IMPLIED_NAK_SEQUENCE_RETRY_CNT += 1

    return resp_pkt, save_resp_pkt


def implied_nak_sequence_error_retry_exceeded_hook(resp_pkt, save_resp_pkt):
    import roce

    global IMPLIED_NAK_SEQUENCE_RETRY_EXCEEDED_CNT

    if resp_pkt[roce.BTH].psn == 0:
        if IMPLIED_NAK_SEQUENCE_RETRY_EXCEEDED_CNT == 0:
            resp_pkt[roce.BTH].psn = 1
            IMPLIED_NAK_SEQUENCE_RETRY_EXCEEDED_CNT += 1

    return resp_pkt, save_resp_pkt


def sim_unsupported_opcode_hook(wr_ssn, req_pkt, real_send):
    import roce

    req_pkt[roce.BTH].opcode = 31
    return wr_ssn, req_pkt, real_send


def rxe_unsupported_opcode_hook(pkt):
    import roce

    pkt[roce.BTH].opcode = 31
    return pkt


def sim_unexpected_opcode_hook(wr_ssn, req_pkt, real_send):
    import roce
    from roce_enum import RC

    if req_pkt[roce.BTH].psn == 3:
        # replace RC.RDMA_WRITE_LAST with RC.RDMA_WRITE_MIDDLE may not be detected by rxe
        # req_pkt[roce.BTH].opcode = RC.RDMA_WRITE_MIDDLE
        req_pkt[roce.BTH].opcode = RC.RDMA_READ_REQUEST
    return wr_ssn, req_pkt, real_send


def rxe_unexpected_opcode_hook(pkt):
    import roce
    from roce_enum import RC

    if pkt[roce.BTH].psn == 3:
        pkt[roce.BTH].opcode = RC.RDMA_READ_REQUEST
    return pkt


def sim_rkey_violation_hook(wr_ssn, req_pkt, real_send):
    import roce

    req_pkt[roce.RETH].rkey = 0
    return wr_ssn, req_pkt, real_send


def rxe_rkey_violation_hook(pkt):
    import roce

    pkt[roce.RETH].rkey = 0
    return pkt


def length_err_hook(resp_pkt, save_resp_pkt):
    from scapy.all import Raw

    resp_pkt[Raw].load = resp_pkt[Raw].load[0:1]
    return resp_pkt, save_resp_pkt


def bad_response_hook(resp_pkt, save_resp_pkt):
    import roce
    from roce_enum import RC

    if resp_pkt[roce.BTH].psn == 3:
        resp_pkt[roce.BTH].opcode = RC.RDMA_READ_RESPONSE_MIDDLE
    return resp_pkt, save_resp_pkt


def ghost_ack_hook(resp_pkt, save_resp_pkt):
    import roce

    resp_pkt[roce.BTH].psn = 1
    return resp_pkt, save_resp_pkt
