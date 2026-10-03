from workers.common.runner import WorkerRunner
from workers.mapcidr.adapter import MapcidrAdapter

if __name__ == "__main__":
    WorkerRunner(MapcidrAdapter()).run_forever()
