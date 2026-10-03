from workers.common.runner import WorkerRunner
from workers.uncover.adapter import UncoverAdapter

if __name__ == "__main__":
    WorkerRunner(UncoverAdapter()).run_forever()
