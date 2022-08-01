from enum import IntEnum


class HOOK_TYPE(IntEnum):
    SEND = 0
    RECV = 1


def sim_read_partial_retry_hook(pkt):
    import roce

    if pkt[roce.BTH].psn == 4:
        pkt[roce.BTH].psn = 1
    return pkt
