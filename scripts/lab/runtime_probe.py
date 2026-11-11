import json,socket,threading,sys,os
from pathlib import Path
product=sys.argv[1]
if product not in {'codex','claude-code','offline'}:raise SystemExit('unsupported probe label')
base=Path.home()/'lab/asgp-p23';target=base/('runtime-'+product+'.proof')
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);port=listener.getsockname()[1]
def accept():
 connection,_=listener.accept();connection.recv(32);connection.sendall(b'OK');connection.close();listener.close()
thread=threading.Thread(target=accept);thread.start()
target.write_text('ASGP_P2_RUNTIME_OK');assert target.read_text()=='ASGP_P2_RUNTIME_OK'
client=socket.create_connection(('127.0.0.1',port),timeout=3);client.sendall(b'ASGP_SAFE_PROBE');assert client.recv(2)==b'OK';client.close();thread.join()
result={'product':product,'pid':os.getpid(),'ppid':os.getppid(),'path':str(target),'host':'127.0.0.1','port':port,'result':'passed'}
(base/('runtime-'+product+'-metadata.json')).write_text(json.dumps(result))
print(json.dumps(result))
