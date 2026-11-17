#!/usr/bin/env python3
"""Build platform archives without modifying host applications or startup."""
import hashlib,json,os,pathlib,plistlib,shutil,subprocess,tempfile,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1];os.chdir(ROOT)
OUT=ROOT/'dist';OUT.mkdir(exist_ok=True)
GO=os.environ.get('GO','go');VERSION='0.1.0-beta.1'
for system,arch in [('darwin','arm64'),('darwin','amd64'),('windows','amd64'),('windows','arm64')]:
 name=f'LOCKLANE-{VERSION}-{system}-{arch}'
 with tempfile.TemporaryDirectory() as td:
  folder=pathlib.Path(td)/name;folder.mkdir()
  if system=='darwin':
   app=folder/'LOCKLANE.app';binary=app/'Contents/MacOS/LOCKLANE';binary.parent.mkdir(parents=True)
   launcher=app/'Contents/MacOS/Launch';launcher.write_text('#!/bin/sh\numask 077\nmkdir -p "$HOME/Library/Logs"\n"$(dirname "$0")/LOCKLANE" > "$HOME/Library/Logs/LOCKLANE.log" 2>&1 &\n');launcher.chmod(0o755)
   (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'content.leo.locklane','CFBundleName':'LOCKLANE','CFBundleExecutable':'Launch','CFBundlePackageType':'APPL','CFBundleShortVersionString':VERSION,'LSUIElement':True}))
   install=folder/'Install.command';install.write_text('#!/bin/sh\nset -eu\ncd "$(dirname "$0")"\nmkdir -p "$HOME/Applications"\nif [ -e "$HOME/Applications/LOCKLANE.app" ]; then echo "LOCKLANE already exists. Move the previous app aside before installing."; exit 1; fi\ncp -R LOCKLANE.app "$HOME/Applications/LOCKLANE.app"\nopen "$HOME/Applications/LOCKLANE.app"\n');install.chmod(0o755)
  else:
   binary=folder/'LOCKLANE.exe'
   (folder/'Install.ps1').write_text("$ErrorActionPreference='Stop'\n$dest=Join-Path $env:LOCALAPPDATA 'LOCKLANE'\nif(Test-Path $dest){throw 'LOCKLANE already exists. Back up the previous app first.'}\nNew-Item -ItemType Directory -Path $dest | Out-Null\nCopy-Item (Join-Path $PSScriptRoot 'LOCKLANE.exe') $dest\n$s=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'LOCKLANE.lnk'))\n$s.TargetPath=Join-Path $dest 'LOCKLANE.exe';$s.Save()\nStart-Process (Join-Path $dest 'LOCKLANE.exe')\n")
  env=os.environ.copy();env.update(GOOS=system,GOARCH=arch,CGO_ENABLED='0')
  subprocess.run([GO,'build','-trimpath','-ldflags=-s -w','-o',str(binary),'.'],env=env,check=True)
  if system=='darwin' and os.uname().sysname=='Darwin':subprocess.run(['codesign','--force','--sign','-','--timestamp=none',str(app)],check=True)
  for f in ['README.md','LICENSE','SECURITY.md','COMPATIBILITY.md','THIRD_PARTY.md']:shutil.copyfile(ROOT/f,folder/f)
  shutil.copytree(ROOT/'docs',folder/'docs')
  with zipfile.ZipFile(OUT/(name+'.zip'),'w',compression=zipfile.ZIP_DEFLATED) as z:
   for p in folder.rglob('*'):
    if p.is_file():z.write(p,p.relative_to(folder.parent))
checks=[]
for p in sorted(OUT.glob('*.zip')):checks.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name)
(OUT/'SHA256SUMS.txt').write_text('\n'.join(checks)+'\n')
print('\n'.join(checks))
