from enum import IntEnum


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
