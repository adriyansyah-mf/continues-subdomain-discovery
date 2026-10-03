from workers.common.runner import WorkerRunner
from workers.tlsx.adapter import TlsxAdapter

if __name__ == "__main__":
    WorkerRunner(TlsxAdapter()).run_forever()
