from workers.common.runner import WorkerRunner
from workers.nuclei.adapter import NucleiAdapter

if __name__ == "__main__":
    WorkerRunner(NucleiAdapter()).run_forever()
