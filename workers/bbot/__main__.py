from workers.bbot.adapter import BbotAdapter
from workers.common.runner import WorkerRunner

if __name__ == "__main__":
    WorkerRunner(BbotAdapter()).run_forever()
