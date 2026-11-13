"""至少一次上报：成功未 ack 后崩溃可重发，服务端按稳定 ID 去重。

每个周期结束时报一条覆盖度对账：本周期送达多少、永久失败多少、因容量丢了
多少、当前积压多少。没有这条记录，服务端看到"没有事件"时无法区分"没发生"
和"端侧已经装满了"。
"""
import argparse
import fcntl
import json
import time
import urllib.error
import urllib.request
from endpoint.config import load
from endpoint.coverage import emit, stamp
from endpoint.outbox import Outbox


def flush(config):
    outbox = Outbox(config['state_dir'])
    lock = (outbox.root/'flush.lock').open('a')
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'busy':True, 'sent':0, 'dead':0}
        started=time.time()
        with outbox.db:
            outbox.db.execute("UPDATE outbox SET state='pending' WHERE state='inflight'")
            outbox.db.execute("DELETE FROM outbox WHERE state='sent' AND updated_at<?", (time.time()-7*86400,))
        outbox.db.execute('PRAGMA wal_checkpoint(PASSIVE)')
        stats = {'sent':0, 'dead':0, 'pending':0}
        while True:
            row = outbox.db.execute("SELECT * FROM outbox WHERE state='pending' ORDER BY seq LIMIT 1").fetchone()
            if not row or row['next_attempt'] > time.time():
                break
            with outbox.db:
                outbox.db.execute("UPDATE outbox SET state='inflight' WHERE seq=?", (row['seq'],))
            request = urllib.request.Request(config['server_base_url'].rstrip('/')+row['endpoint'],
                data=row['payload'].encode(), headers={'Authorization':'Bearer '+config['device_token'], 'Content-Type':'application/json'}, method='POST')
            state, error = 'sent', None
            try:
                # Do not follow a redirect with device credentials.
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *args, **kwargs): return None
                with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
                    json.loads(response.read(1024*1024))
            except urllib.error.HTTPError as exc:
                state = 'pending' if exc.code in (408, 429) or exc.code >= 500 else 'dead'
                error = 'http_'+str(exc.code)
            except Exception:
                state, error = 'pending', 'transport_error'
            attempts = row['attempts']+1
            if state == 'pending' and attempts >= config.get('max_attempts', 20):
                state, error = 'dead', 'retry_limit'
            with outbox.db:
                outbox.db.execute('UPDATE outbox SET state=?,attempts=?,next_attempt=?,last_error=?,updated_at=? WHERE seq=?',
                    (state, attempts, time.time()+min(2**min(attempts,9),300), error, time.time(), row['seq']))
            stats[state] += 1
            if state == 'pending':
                break
        if stats['dead']:
            # 重试上限耗尽即永久丢失，和容量封顶一样必须留痕。
            outbox.record_drop('retry_limit', stats['dead'], detail='exceeded max_attempts')
        emit(outbox, config, period_start=stamp(started), period_end=stamp(time.time()),
             delivered=stats['sent'], dead=stats['dead'])
        return stats
    finally:
        lock.close()
        outbox.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--watch', action='store_true');parser.add_argument('--once', action='store_true');args=parser.parse_args()
    while True:
        print(json.dumps(flush(load())), flush=True)
        if not args.watch:return
        time.sleep(5)


if __name__ == '__main__':main()
