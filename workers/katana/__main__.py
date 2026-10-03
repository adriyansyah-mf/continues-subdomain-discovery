from workers.common.runner import WorkerRunner
from workers.katana.adapter import KatanaAdapter

if __name__ == "__main__":
    WorkerRunner(KatanaAdapter()).run_forever()
