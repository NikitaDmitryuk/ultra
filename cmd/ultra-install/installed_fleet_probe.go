package main

const recoveryPreparationFleetIdentityProgram = `import os,stat,pwd,subprocess
from pathlib import Path
root=Path('/etc/ultra-fleet')
for path in [root,*root.parents]:
 info=path.lstat()
 assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
allowed={0,pwd.getpwnam('ultra-relay').pw_uid}
for name,private in [('id_ed25519',True),('id_ed25519.pub',False)]:
 path=root/name;info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid in allowed and info.st_nlink==1
 assert not info.st_mode&(0o077 if private else 0o022)
result=subprocess.run(['/usr/bin/ssh-keygen','-y','-P','','-f',str(root/'id_ed25519')],capture_output=True,text=True,timeout=5)
assert result.returncode==0
actual=result.stdout.strip().split()
expected=(root/'id_ed25519.pub').read_text().strip().split()
assert len(actual)>=2 and actual[0]=='ssh-ed25519' and len(expected)>=2 and expected[:2]==actual[:2]
`
