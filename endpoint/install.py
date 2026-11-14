"""仅在明确指定端点安装；备份、幂等、冲突检测与精确卸载。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

EVENTS = ('SessionStart', 'PreToolUse', 'PostToolUse', 'SessionEnd')
QWEN_EVENTS = ('SessionStart', 'PreToolUse', 'PostToolUse')
BEGIN = '# BEGIN ASGP ENDPOINT'
END = '# END ASGP ENDPOINT'


def _product_events(product):
    return QWEN_EVENTS if product == 'qwen-code' else EVENTS


def _settings_path(home, product):
    if product == 'codex':
        return home / '.codex/config.toml'
    if product == 'qwen-code':
        return home / '.qwen/settings.json'
    return home / '.claude/settings.json'


def private_write(path, data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if isinstance(data,str):data=data.encode()
    temporary=path.with_name(path.name+'.asgp-tmp')
    fd=os.open(temporary,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
    with os.fdopen(fd,'wb') as h:h.write(data);h.flush();os.fsync(h.fileno())
    os.replace(temporary,path)
    os.chmod(path,0o600)


def hook_command(root, config_path, product):
    return 'cd '+shlex.quote(str(root))+' && ASGP_ENDPOINT_CONFIG='+shlex.quote(str(config_path))+' '+shlex.quote(sys.executable)+' -m endpoint.hook '+product


def hook_listing(cwd):
    proc=subprocess.Popen(['codex','app-server'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,text=True,bufsize=1)
    def send(value):proc.stdin.write(json.dumps(value)+'\n');proc.stdin.flush()
    try:
        send({'id':1,'method':'initialize','params':{'clientInfo':{'name':'asgp-installer','version':'1.0'},'capabilities':{'experimentalApi':True}}})
        while True:
            line=proc.stdout.readline()
            if not line:raise RuntimeError('codex_initialization_failed')
            if json.loads(line).get('id')==1:break
        send({'method':'initialized'})
        send({'id':2,'method':'hooks/list','params':{'cwds':[str(cwd)]}})
        while True:
            line=proc.stdout.readline()
            if not line:raise RuntimeError('codex_hook_listing_failed')
            result=json.loads(line)
            if result.get('id')==2:
                if 'error' in result:raise RuntimeError('codex_hook_listing_failed')
                return [h for group in result['result']['data'] for h in group['hooks']]
    finally:
        proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()


def install(home, root, config_path, products, *, print_only=False):
    state=Path(config_path).parent
    manifest_path=state/'installation.json'
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    plans=[]
    configuration=json.loads(Path(config_path).read_text()) if Path(config_path).exists() else {}
    approval_enabled=configuration.get('approval_mode')=='control_plane'
    for product in products:
        path=_settings_path(home,product)
        events=_product_events(product)
        command=hook_command(root,config_path,product)
        if product in manifest:
            if hashlib.sha256(path.read_bytes()).hexdigest()==manifest[product]['installed_sha256']:
                plans.append((product,'already_installed'));continue
            raise RuntimeError('configuration_changed_since_installation')
        original=path.read_bytes() if path.exists() else b''
        if product=='codex':
            if BEGIN.encode() in original:raise RuntimeError('orphaned_asgp_configuration')
            extra='\n'+BEGIN+'\n'
            for event in events:
                timeout=25 if approval_enabled and event=='PreToolUse' else 3
                extra+='[[hooks.'+event+']]\n[[hooks.'+event+'.hooks]]\ntype = "command"\ncommand = '+json.dumps(command)+'\ntimeout = '+str(timeout)+'\n'
            installed=original+extra.encode()
        else:
            data=json.loads(original or b'{}')
            hooks=data.setdefault('hooks',{})
            for event in events:
                timeout=25 if approval_enabled and event=='PreToolUse' else 3
                hooks.setdefault(event,[]).append({'hooks':[{'type':'command','command':command,'timeout':timeout}]})
            installed=(json.dumps(data,indent=2,ensure_ascii=False)+'\n').encode()
        plans.append((product,'install'))
        if print_only:continue
        backup=state/(product+'-config.before')
        if backup.exists():raise RuntimeError('backup_exists_without_manifest')
        private_write(backup,original)
        private_write(path,installed)
        try:
            if product=='codex':
                metadata=hook_listing(root)
                own=[h for h in metadata if h.get('command')==command]
                if len(own)!=4:raise RuntimeError('expected_four_codex_hooks')
                for hook in own:
                    installed+=('[hooks.state.'+json.dumps(hook['key'])+']\ntrusted_hash = '+json.dumps(hook['currentHash'])+'\n').encode()
                installed+=(END+'\n').encode()
                private_write(path,installed)
            manifest[product]={'path':str(path),'backup':str(backup),'existed':bool(original),
                'installed_sha256':hashlib.sha256(installed).hexdigest()}
            private_write(manifest_path,json.dumps(manifest,indent=2))
        except Exception:
            if original:private_write(path,original)
            else:path.unlink(missing_ok=True)
            backup.unlink(missing_ok=True)
            raise
    return plans


def uninstall(config_path):
    manifest_path=Path(config_path).parent/'installation.json'
    if not manifest_path.exists():return []
    manifest=json.loads(manifest_path.read_text())
    # Validate all files first: never partially restore over another writer's changes.
    for entry in manifest.values():
        if hashlib.sha256(Path(entry['path']).read_bytes()).hexdigest()!=entry['installed_sha256']:
            raise RuntimeError('configuration_changed_since_installation: merge manually using saved backup')
    restored=[]
    for product,entry in manifest.items():
        path=Path(entry['path']);backup=Path(entry['backup'])
        if entry['existed']:private_write(path,backup.read_bytes())
        else:path.unlink()
        backup.unlink();restored.append(product)
    manifest_path.unlink()
    return restored


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True);parser.add_argument('--product',action='append',choices=['codex','claude-code','qwen-code'])
    parser.add_argument('--print',dest='print_only',action='store_true');parser.add_argument('--uninstall',action='store_true')
    args=parser.parse_args();path=Path(args.config).resolve()
    if args.uninstall:print(json.dumps({'restored':uninstall(path)}));return
    root=Path(__file__).resolve().parents[1]
    products=args.product or ['codex','claude-code']
    config=json.loads(path.read_text())
    fingerprints={}
    for product in products:
        bin_name='qwen' if product=='qwen-code' else 'claude' if product=='claude-code' else 'codex'
        binary=shutil.which(bin_name)
        if not binary:raise RuntimeError('product_binary_missing')
        version=subprocess.check_output([binary,'--version'],text=True,timeout=10).strip()
        expected=config['product_versions'][product]
        tokens=version.split()
        actual=tokens[1] if product=='codex' and len(tokens)>1 else tokens[0]
        if actual != expected and expected not in tokens:
            raise RuntimeError('configured_product_version_does_not_match_binary')
        binary=Path(binary).resolve()
        binaries=[binary]
        if product=='codex':
            # npm launcher can stay unchanged while its platform binary changes.
            binaries.extend(binary.parents[2].glob('codex-linux*/vendor/**/bin/codex'))
            binaries.extend(binary.parents[1].glob('vendor/**/bin/codex'))
        files=[]
        for file in binaries:
            stat=file.stat()
            files.append({'path':str(file),'stat':[stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns],'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
        fingerprints[product]={'files':files}
    plans=install(Path.home(),root,path,products,print_only=args.print_only)
    if not args.print_only:
        config.setdefault('binary_fingerprints',{}).update(fingerprints)
        private_write(path,json.dumps(config,indent=2))
    print(json.dumps({'products':plans}))


if __name__=='__main__':main()
