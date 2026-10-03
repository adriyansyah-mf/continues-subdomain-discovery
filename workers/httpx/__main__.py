from workers.common.runner import WorkerRunner
from workers.httpx.adapter import HttpxAdapter

if __name__ == "__main__":
    WorkerRunner(HttpxAdapter()).run_forever()
