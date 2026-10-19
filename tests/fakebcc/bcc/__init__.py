"""Minimal stand-in for BCC: loads nothing, polls sleep. Used by test_process_run."""
import time
class _T:
    def open_perf_buffer(self, cb, page_cnt, lost_cb): pass
class BPF:
    def __init__(self, text): pass
    @staticmethod
    def tracepoint_exists(c, e): return True
    def __getitem__(self, k): return _T()
    def perf_buffer_poll(self, timeout): time.sleep(timeout / 1000.0)
