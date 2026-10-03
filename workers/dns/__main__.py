from workers.common.runner import WorkerRunner
from workers.dns.adapter import DnsAdapter

if __name__ == "__main__":
    WorkerRunner(DnsAdapter()).run_forever()
