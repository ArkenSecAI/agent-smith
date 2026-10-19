#!/usr/bin/env python3
"""Build a broad Kali development image inside KVM, without root on the host.

Inputs come from agent-smith-assets-linux.py. Installation is a trusted artifact
build with repository access, distinct from restricted project networking.
The output is an unsealed build disk until runtime qualification records its
installed manifest and guest implementation and produces an ImageManifest.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time

PACKAGES = ['kali-linux-default', 'kali-desktop-xfce', 'ghidra', 'gdb', 'radare2',
            'tshark', 'metasploit-framework', 'mitmproxy', 'zaproxy', 'burpsuite',
            'firefox-esr', 'mcp-kali-server=0.0~git20260317.00154c0-0kali2',
            'hexstrike-ai=0.0~git20260803.d689933-0kali1', 'python3-mcp', 'patch']


def sha(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def run(args, cwd, env):
    subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True, stdin=subprocess.DEVNULL)


def cpio_file(name, data, ino):
    filename = name.encode() + b'\0'
    values = [ino, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(filename), 0]
    header = b'070701' + b''.join(f'{value:08x}'.encode() for value in values)
    prefix = header + filename
    return prefix + bytes((-len(prefix)) % 4) + data + bytes((-len(data)) % 4)


def qmp_kvm(path, process):
    end = time.monotonic() + 30
    while True:
        if process.poll() is not None:
            raise RuntimeError('QEMU exited before QMP startup')
        try:
            connection = socket.socket(socket.AF_UNIX)
            connection.connect(str(path))
            break
        except (FileNotFoundError, ConnectionRefusedError):
            connection.close()
            if time.monotonic() > end:
                raise TimeoutError('QMP startup timeout')
            time.sleep(0.1)
    connection.settimeout(15)
    stream = connection.makefile('rwb', buffering=0)
    greeting = json.loads(stream.readline())
    if 'QMP' not in greeting:
        raise RuntimeError('missing QMP greeting')
    def invoke(op):
        stream.write(json.dumps({'execute': op, 'id': op}).encode() + b'\n')
        while True:
            answer = json.loads(stream.readline())
            if answer.get('id') == op:
                if 'error' in answer:
                    raise RuntimeError(str(answer['error']))
                return answer['return']
    invoke('qmp_capabilities')
    state = invoke('query-kvm')
    stream.close()
    connection.close()
    if state != {'enabled': True, 'present': True}:
        raise RuntimeError(f'hardware acceleration is not active: {state}')
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', required=True, type=Path)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--guest-code', required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run without host root privileges')
    os.umask(0o077)
    root = args.directory.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    assets = args.assets.absolute()
    runtime = assets / 'qemu/runtime'
    qemu_receipt = json.loads((assets / 'qemu/runtime.json').read_text())
    kali_receipt = json.loads((assets / 'kali/receipt.json').read_text())
    qemu = Path(qemu_receipt['binary'])
    image_tool = Path(qemu_receipt['imageBinary'])
    if sha(qemu) != qemu_receipt['sha256'] or sha(image_tool) != qemu_receipt['imageSha256']:
        raise ValueError('QEMU artifact pin mismatch')
    iso_record = next(row for row in kali_receipt['assets'] if row['file'].endswith('.iso'))
    iso = assets / 'kali' / iso_record['file']
    if sha(iso) != iso_record['sha256'] or kali_receipt['fingerprint'] != '827C8569F2518CC677FECA1AED65462EC8D5E4C5':
        raise ValueError('Kali input pin mismatch')
    env = {'PATH': f'{runtime / "usr/bin"}:/usr/bin:/bin', 'HOME': str(root / 'home'),
           'LD_LIBRARY_PATH': qemu_receipt['libraryDir'], 'LANG': 'C.UTF-8'}
    (root / 'home').mkdir(mode=0o700)
    extracted = root / 'installer'
    extracted.mkdir()
    run([runtime / 'usr/lib/7zip/7z', 'x', f'-o{extracted}', iso,
         'install.amd/vmlinuz', 'install.amd/initrd.gz'], root, env)
    seed = root / 'seed'
    guest = seed / 'guest'
    guest.mkdir(parents=True)
    inputs = {}
    for name in ('supervisor.py', 'mcp_runner.py', 'agent-smith-guest.service'):
        source = args.guest_code / name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f'guest implementation is missing or a symlink: {name}')
        inputs[name] = sha(source)
        shutil.copyfile(source, guest / name)
    patch_dir = seed / 'patches'
    patch_dir.mkdir()
    for name in ('mcp-kali-timeout.patch', 'hexstrike-timeout.patch'):
        source = args.guest_code.parent / 'patches' / name
        inputs[name] = sha(source)
        shutil.copyfile(source, patch_dir / name)
    setup = '''#!/bin/sh
set -eu
mkdir -p /target/opt/agent-smith /target/work /target/var/lib/agent-smith
cp -a /mnt/asbuild/guest/. /target/opt/agent-smith/
cp /mnt/asbuild/guest/agent-smith-guest.service /target/etc/systemd/system/
cp -a /mnt/asbuild/patches /target/opt/agent-smith/
printf '%s\\n' 'cd30f9b04ad9bb0896fd4368ed22330ff7798469cbc255c9ae6e7385b79d0484  /usr/share/mcp-kali-server/server.py' '543aae46f591ff5705f1a33dcf211ab9eec15d80435d68a107526a14492e9f31  /usr/share/hexstrike-ai/hexstrike_server.py' > /target/opt/agent-smith/upstream-sha256
in-target sha256sum --check /opt/agent-smith/upstream-sha256
in-target patch --batch --fuzz=0 -d / -p1 -i /opt/agent-smith/patches/mcp-kali-timeout.patch
in-target patch --batch --fuzz=0 -d / -p1 -i /opt/agent-smith/patches/hexstrike-timeout.patch
printf '%s\\n' qemu_fw_cfg > /target/etc/modules-load.d/agent-smith.conf
in-target systemctl enable agent-smith-guest.service
# Runtime wall time comes from QEMU's UTC RTC; target-only networking has no NTP route.
# The unused network-time service can otherwise hold shutdown past its bound.
in-target systemctl mask systemd-timesyncd.service
# No reusable password, SSH service or automatic login in the resulting image.
in-target passwd -l root
in-target passwd -l smith
in-target systemctl disable ssh.service || true
mkdir -p /target/opt/agent-smith/image
in-target dpkg-query -W '-f=${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\n' > /target/opt/agent-smith/image/packages.tsv
cp /mnt/asbuild/recipe.json /target/opt/agent-smith/image/recipe.json
'''
    (seed / 'setup.sh').write_text(setup)
    recipe = {'schema': 1, 'installer': iso_record, 'guestInputs': inputs,
              'requestedPackages': PACKAGES, 'network': 'trusted package provisioning only',
              'repository': 'https://http.kali.org/kali kali-rolling',
              'runtimeClock': 'host-backed QEMU UTC RTC; systemd-timesyncd permanently masked',
              'authentication': 'Signed whole-ISO checksum authenticates installation media; network packages require APT Release/package verification.',
              'reproducibilityLimit': 'Rolling package versions are fixed by the resulting installed manifest, not a permanent upstream snapshot.'}
    (seed / 'recipe.json').write_text(json.dumps(recipe, indent=2) + '\n')
    seed_archive = root / 'seed.tar.gz'
    run(['/usr/bin/tar', '--sort=name', '--mtime=@0', '--owner=0', '--group=0', '--numeric-owner',
         '-czf', seed_archive, '-C', seed, '.'], root, env)
    preseed = f'''d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us
# The target package asks variant separately from the installer keymap.
keyboard-configuration keyboard-configuration/variant select English (US)
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string agent-smith-kali
d-i netcfg/get_domain string local
d-i hw-detect/load_firmware boolean false
d-i mirror/country string manual
d-i mirror/protocol select https
d-i mirror/https/hostname string http.kali.org
d-i mirror/https/directory string /kali
d-i mirror/https/proxy string
d-i mirror/suite string kali-rolling
d-i mirror/udeb/suite string kali-rolling
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/user-fullname string Agent Smith
d-i passwd/username string smith
d-i passwd/user-password-crypted password !
d-i clock-setup/utc boolean true
d-i time/zone string Etc/UTC
d-i clock-setup/ntp boolean false
d-i partman-auto/disk string /dev/vda
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-basicfilesystems/no_swap boolean false
d-i apt-setup/non-free boolean true
d-i apt-setup/contrib boolean true
d-i apt-setup/non-free-firmware boolean true
d-i apt-setup/services-select multiselect
tasksel tasksel/first multiselect standard
d-i pkgsel/include string {' '.join(PACKAGES)}
d-i pkgsel/upgrade select none
popularity-contest popularity-contest/participate boolean false
wireshark-common wireshark-common/install-setuid boolean false
kismet-capture-common kismet-capture-common/install-setuid boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/vda
d-i preseed/late_command string mkdir -p /mnt/asbuild; tar -xzf /asbuild.tar.gz -C /mnt/asbuild && sh /mnt/asbuild/setup.sh
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/poweroff boolean true
'''
    (root / 'preseed.cfg').write_text(preseed)
    initrd = root / 'preseed-initrd.gz'
    shutil.copyfile(extracted / 'install.amd/initrd.gz', initrd)
    with open(initrd, 'ab') as output:
        archive = (cpio_file('preseed.cfg', preseed.encode(), 1)
                   + cpio_file('asbuild.tar.gz', seed_archive.read_bytes(), 2)
                   + cpio_file('TRAILER!!!', b'', 3))
        output.write(gzip.compress(archive, mtime=0))
    disk = root / 'installed.qcow2'
    run([image_tool, 'create', '-f', 'qcow2', disk, '48G'], root, env)
    # All paths passed to QEMU are owned and selected by the builder, not a model.
    arguments = [str(qemu), '-nodefaults', '-no-user-config', '-accel', 'kvm', '-machine', 'q35', '-cpu', 'host',
                 '-m', '3072', '-smp', '4', '-L', qemu_receipt['firmwareDir'],
                 '-display', 'none', '-monitor', 'none', '-no-reboot',
                 '-qmp', f'unix:{root / "qmp.sock"},server=on,wait=off',
                 '-serial', 'stdio', '-kernel', str(extracted / 'install.amd/vmlinuz'),
                 '-initrd', str(initrd), '-append', 'auto=true priority=critical console=ttyS0,115200n8',
                 '-drive', f'file={disk},format=qcow2,if=virtio',
                 '-drive', f'file={iso},media=cdrom,readonly=on,index=0',
                 '-netdev', 'user,id=install', '-device', 'virtio-net-pci,netdev=install',
                 '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']
    # The trusted installer can fetch packages but cannot see the operator's home.
    confined = ['/usr/bin/bwrap', '--unshare-all', '--share-net', '--die-with-parent', '--new-session',
                '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
                '--ro-bind', '/etc/ld.so.cache', '/etc/ld.so.cache',
                '--ro-bind', '/etc/resolv.conf', '/etc/resolv.conf', '--proc', '/proc', '--dev', '/dev',
                '--dev-bind', '/dev/kvm', '/dev/kvm', '--tmpfs', '/tmp',
                '--ro-bind', str(runtime), str(runtime), '--ro-bind', str(iso), str(iso),
                '--bind', str(root), str(root), '--chdir', str(root), '--', *arguments]
    started = time.time()
    with open(root / 'installer.log', 'xb') as log:
        with subprocess.Popen(confined, cwd=root, env=env, stdin=subprocess.DEVNULL,
                              stdout=log, stderr=subprocess.STDOUT) as process:
            try:
                kvm = qmp_kvm(root / 'qmp.sock', process)
                (root / 'acceleration.json').write_text(json.dumps(kvm) + '\n')
                code = process.wait(timeout=7200)
            except BaseException:
                process.kill()
                process.wait()
                raise
    if code:
        raise RuntimeError(f'installer QEMU exited {code}; retained original installer.log')
    # A clean QEMU exit alone is not an installation success or a sealed image.
    result = {'schema': 1, 'state': 'installer-exited-awaiting-guest-qualification',
              'exitCode': code, 'seconds': round(time.time()-started, 2), 'kvm': kvm,
              'disk': str(disk), 'recipe': recipe, 'installerLogSha256': sha(root / 'installer.log')}
    (root / 'installation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
