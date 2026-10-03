# ipranges

No separate worker: provider IP ranges (lord-alfred/ipranges) are synced by the scheduler
(`IPRANGES_SYNC_INTERVAL`, default daily) or on demand with `bbctl sync ipranges`
(`app/services/ipranges.py`). Workers use `CloudRangeIndex` to enrich IPs; ranges are never scope.
