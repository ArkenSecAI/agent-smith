#!/usr/bin/env python3
"""Acquire development assets into an owned directory; never install host packages.

Ubuntu packages are verified by APT against a separate signed repository state.
Kali images require the published signing fingerprint and a matching SHA256.
Model files use an immutable upstream revision and its published LFS digest.
This is development-image tooling, not a supported installer/release command.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.parse
import urllib.request

KALI_KEY = '827C8569F2518CC677FECA1AED65462EC8D5E4C5'
KALI_ISO = 'kali-linux-2026.2-installer-netinst-amd64.iso'
KALI_SHA = 'd32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b'
LLAMA_REV = 'd81235049384534c167caea52b85a694f6103d14'
MODEL_REPO = 'unsloth/Qwen3.5-9B-GGUF'
MODEL_REV = '3885219b6810b007914f3a7950a8d1b469d598a5'
MODEL_FILE = 'Qwen3.5-9B-Q4_K_M.gguf'
MODEL_SHA = '03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8'
MODEL_BASE_REPO = 'Qwen/Qwen3.5-9B'
MODEL_BASE_REV = 'c202236235762e1c871ad0ccb60c8ee5ba337b9a'
MODEL_LICENSE_URL = f'https://huggingface.co/{MODEL_BASE_REPO}/raw/{MODEL_BASE_REV}/LICENSE'
MODEL_LICENSE_SHA = 'bbedc3fda3305820b977265f01b8619d87570a6739de3a5582c3464840f1e57a'
UBUNTU_KEY_SHA = '80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31'


def digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.new')
    with open(temporary, 'x', encoding='utf-8') as output:
        json.dump(value, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def download(url, path, expected=None):
    if not url.startswith('https://'):
        raise ValueError('acquisition requires HTTPS')
    if path.is_symlink():
        raise ValueError('refusing symlink download destination')
    if path.exists():
        if expected is None or digest(path) != expected:
            raise ValueError(f'existing unverified asset: {path.name}')
        return {'url': url, 'file': path.name, 'sha256': expected, 'bytes': path.stat().st_size}
    temporary = path.with_suffix(path.suffix + '.partial')
    if temporary.exists():
        raise ValueError(f'incomplete prior download retained: {temporary}; inspect before retry')
    request = urllib.request.Request(url, headers={'User-Agent': 'Agent-Smith-development-assets/1'})
    with urllib.request.urlopen(request, timeout=120) as response, open(temporary, 'xb') as output:
        final = urllib.parse.urlsplit(response.url)
        if final.scheme != 'https':
            raise ValueError('insecure artifact redirect')
        checksum = hashlib.sha256()
        while block := response.read(1024 * 1024):
            checksum.update(block)
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    actual = checksum.hexdigest()
    if expected is not None and actual != expected:
        raise ValueError(f'asset hash mismatch: {path.name}')
    os.replace(temporary, path)
    # Never retain signed CDN query strings.
    return {'url': url, 'resolvedOrigin': final.netloc, 'file': path.name,
            'sha256': actual, 'bytes': path.stat().st_size}


def command(args, root, env=None, timeout=1800):
    clean = {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home'), 'LANG': 'C.UTF-8',
             'LC_ALL': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'}
    if env:
        clean.update(env)
    print('$', ' '.join(map(str, args)), flush=True)
    result = subprocess.run(list(map(str, args)), cwd=root, env=clean,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout, text=True)
    print(result.stdout, end='', flush=True)
    if result.returncode:
        raise RuntimeError(f'command exited {result.returncode}: {args[0]}')
    return result.stdout


def qemu_firmware(root):
    receipt_path = root / 'receipt.json'
    receipt = json.loads(receipt_path.read_text())
    for package in receipt['packages']:
        if digest(root / 'packages' / package['file']) != package['sha256']:
            raise ValueError('authenticated QEMU package archive changed')
    runtime = root / 'runtime'
    firmware = runtime / 'firmware'
    firmware.mkdir(exist_ok=True)
    pins = {}
    for directory in ('usr/share/qemu', 'usr/share/seabios', 'usr/lib/ipxe/qemu'):
        for source in sorted((runtime / directory).iterdir()):
            if not source.is_file():
                continue
            resolved = source.resolve()
            if not resolved.is_relative_to(runtime):
                raise ValueError('firmware link escapes the authenticated runtime')
            checksum = digest(resolved)
            target = firmware / source.name
            if target.exists():
                if digest(target) != checksum:
                    raise ValueError(f'conflicting firmware basename: {source.name}')
            if not target.exists() or target.is_symlink():
                temporary = target.with_suffix(target.suffix + '.new')
                with open(resolved, 'rb') as source_file, open(temporary, 'xb') as output:
                    shutil.copyfileobj(source_file, output)
                os.replace(temporary, target)
            pins[source.name] = checksum
    for name in ('bios-256k.bin', 'vgabios-stdvga.bin', 'efi-virtio.rom'):
        if name not in pins:
            raise ValueError(f'incomplete QEMU firmware bundle: {name}')
    save(root / 'runtime.json', {**receipt, 'firmwareDir': str(firmware),
                                'firmwarePins': pins, 'acquisitionReceiptSha256': digest(receipt_path)})


def qemu(root):
    key = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
    if digest(key) != UBUNTU_KEY_SHA:
        raise ValueError('Ubuntu archive keyring differs from qualified input')
    for name in ('lists/partial', 'cache', 'archives/partial', 'empty', 'packages', 'runtime'):
        (root / name).mkdir(parents=True, exist_ok=True)
    source_list = root / 'sources.list'
    source_list.write_text('\n'.join(
        f'deb [arch=amd64 signed-by={key}] https://archive.ubuntu.com/ubuntu {suite} main universe'
        for suite in ('noble', 'noble-updates', 'noble-security')) + '\n')
    opts = ['-o', f'Dir::Etc::sourcelist={source_list}', '-o', 'Dir::Etc::sourceparts=-',
            '-o', f'Dir::State::lists={root / "lists"}', '-o', f'Dir::Cache={root / "cache"}',
            '-o', f'Dir::Cache::archives={root / "archives"}',
            '-o', 'Dir::Etc::netrc=/dev/null', '-o', f'Dir::Etc::netrcparts={root / "empty"}',
            '-o', 'Acquire::http::Proxy=DIRECT', '-o', 'Acquire::https::Proxy=DIRECT',
            '-o', 'APT::Get::AllowUnauthenticated=false']
    command(['apt-get', *opts, 'update'], root)
    requested = ['qemu-system-x86', 'qemu-utils', '7zip']
    plan = command(['apt-get', *opts, '--simulate', '--no-install-recommends', 'install', *requested], root)
    packages = dict(re.findall(r'^Inst (\S+) \((\S+)', plan, re.MULTILINE))
    # Even already-installed requested binaries must become pinned bundle assets.
    for package in requested:
        if package not in packages:
            policy = command(['apt-cache', *opts, 'policy', package], root)
            match = re.search(r'^\s+Candidate: (\S+)', policy, re.MULTILINE)
            if not match or match[1] == '(none)':
                raise ValueError(f'no package candidate: {package}')
            packages[package] = match[1]
    records = []
    for package, version in sorted(packages.items()):
        metadata = command(['apt-cache', *opts, 'show', f'{package}={version}'], root)
        expected = re.search(r'^SHA256: ([0-9a-f]{64})$', metadata, re.MULTILINE)
        if not expected:
            raise ValueError(f'no authenticated package digest: {package}')
        command(['apt-get', *opts, 'download', f'{package}={version}'], root / 'packages')
        candidates = [p for p in (root / 'packages').glob('*.deb') if digest(p) == expected[1]]
        if len(candidates) != 1:
            raise ValueError(f'download does not match signed package metadata: {package}')
        archive = candidates[0]
        command(['dpkg-deb', '--extract', archive, root / 'runtime'], root)
        records.append({'package': package, 'version': version, 'file': archive.name, 'sha256': expected[1]})
    runtime = root / 'runtime'
    environment = {'LD_LIBRARY_PATH': str(runtime / 'usr/lib/x86_64-linux-gnu')}
    version = command([runtime / 'usr/bin/qemu-system-x86_64', '--version'], root, environment)
    result = {'schema': 1, 'keyringSha256': UBUNTU_KEY_SHA, 'packages': records,
              'signedMetadata': {p.name: digest(p) for p in (root / 'lists').glob('*InRelease')},
              'versionOutput': version,
              'binary': str(runtime / 'usr/bin/qemu-system-x86_64'),
              'sha256': digest(runtime / 'usr/bin/qemu-system-x86_64'),
              'imageBinary': str(runtime / 'usr/bin/qemu-img'),
              'imageSha256': digest(runtime / 'usr/bin/qemu-img'),
              'firmwareDir': str(runtime / 'usr/share/qemu'),
              'libraryDir': environment['LD_LIBRARY_PATH']}
    save(root / 'receipt.json', result)
    qemu_firmware(root)


def kali(root):
    base = 'https://cdimage.kali.org/kali-2026.2/'
    records = [download('https://archive.kali.org/archive-key.asc', root / 'archive-key.asc'),
               download(base + 'SHA256SUMS', root / 'SHA256SUMS'),
               download(base + 'SHA256SUMS.gpg', root / 'SHA256SUMS.gpg')]
    keyhome = root / 'gnupg'
    keyhome.mkdir(mode=0o700)
    command(['gpg', '--no-options', '--homedir', keyhome, '--batch', '--import', root / 'archive-key.asc'], root)
    verified = command(['gpg', '--no-options', '--homedir', keyhome, '--batch', '--status-fd=1',
                        '--verify', root / 'SHA256SUMS.gpg', root / 'SHA256SUMS'], root)
    if f'[GNUPG:] VALIDSIG {KALI_KEY} ' not in verified:
        raise ValueError('Kali signer is not the independently published expected fingerprint')
    hashes = dict((line.split()[1], line.split()[0]) for line in (root / 'SHA256SUMS').read_text().splitlines())
    if hashes.get(KALI_ISO) != KALI_SHA:
        raise ValueError('signed Kali manifest differs from selected point-release image')
    records.append(download(base + KALI_ISO, root / KALI_ISO, KALI_SHA))
    save(root / 'receipt.json', {'schema': 1, 'fingerprint': KALI_KEY, 'verification': verified, 'assets': records})


def model(root):
    api = f'https://huggingface.co/api/models/{MODEL_REPO}/revision/{MODEL_REV}?blobs=true'
    meta_record = download(api, root / 'model-metadata.json')
    metadata = json.loads((root / 'model-metadata.json').read_text())
    if (metadata.get('sha') != MODEL_REV
            or metadata.get('cardData', {}).get('license') != 'apache-2.0'
            or metadata.get('cardData', {}).get('base_model') not in (MODEL_BASE_REPO, [MODEL_BASE_REPO])):
        raise ValueError('model revision, license or declared base changed')
    asset = next(row for row in metadata['siblings'] if row['rfilename'] == MODEL_FILE)
    if asset['lfs']['sha256'] != MODEL_SHA:
        raise ValueError('model digest differs from published immutable revision')
    records = [meta_record, download(f'https://huggingface.co/{MODEL_REPO}/resolve/{MODEL_REV}/{MODEL_FILE}',
                                    root / MODEL_FILE, MODEL_SHA)]
    records.append(download(f'https://huggingface.co/{MODEL_REPO}/raw/{MODEL_REV}/README.md', root / 'QUANTIZATION.md'))
    base_meta = download(f'https://huggingface.co/api/models/{MODEL_BASE_REPO}/revision/{MODEL_BASE_REV}',
                         root / 'base-model-metadata.json')
    base_metadata = json.loads((root / 'base-model-metadata.json').read_text())
    if (base_metadata.get('sha') != MODEL_BASE_REV
            or base_metadata.get('cardData', {}).get('license') != 'apache-2.0'):
        raise ValueError('base-model license revision changed')
    records.append(base_meta)
    records.append(download(f'https://huggingface.co/{MODEL_BASE_REPO}/raw/{MODEL_BASE_REV}/README.md', root / 'MODEL.md'))
    records.append(download(MODEL_LICENSE_URL, root / 'LICENSE', MODEL_LICENSE_SHA))
    (root / MODEL_FILE).chmod(0o400)
    save(root / 'receipt.json', {'schema': 1, 'repo': MODEL_REPO, 'revision': MODEL_REV,
                                'baseModel': MODEL_BASE_REPO, 'baseRevisionObserved': MODEL_BASE_REV,
                                'provenanceLimit': 'Quantization publisher names the base model, not its exact source revision.',
                                'license': 'Apache-2.0', 'licenseSource': MODEL_LICENSE_URL, 'assets': records})


def llama(root, cmake, ninja):
    archive = root / 'source.tar.gz'
    record = download(f'https://codeload.github.com/ggml-org/llama.cpp/tar.gz/{LLAMA_REV}', archive)
    with tarfile.open(archive) as source:
        source.extractall(root, filter='data')
    source_dir = root / f'llama.cpp-{LLAMA_REV}'
    build = root / 'build'
    environment = {'PATH': f'{ninja.parent}:/usr/bin:/bin'}
    command([cmake, '-S', source_dir, '-B', build, '-G', 'Ninja',
             '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_SHARED_LIBS=OFF', '-DGGML_NATIVE=ON', '-DGGML_CUDA=OFF',
             '-DGGML_VULKAN=OFF', '-DGGML_METAL=OFF', '-DGGML_RPC=OFF',
             '-DLLAMA_CURL=OFF', '-DLLAMA_BUILD_TESTS=OFF', '-DLLAMA_BUILD_EXAMPLES=OFF',
             '-DLLAMA_BUILD_SERVER=ON', '-DLLAMA_BUILD_TOOLS=ON'], root, environment)
    command([cmake, '--build', build, '--target', 'llama-server', '-j', '4'], root, environment, 3600)
    binary = build / 'bin/llama-server'
    version = command([binary, '--version'], root)
    help_text = command([binary, '--help'], root)
    (root / 'server-help.txt').write_text(help_text)
    binary.chmod(0o500)
    save(root / 'receipt.json', {'schema': 1, 'release': 'v0.6.0', 'commit': LLAMA_REV,
                                'source': record, 'binary': str(binary), 'sha256': digest(binary),
                                'version': version, 'license': 'MIT',
                                'build': 'CPU-only; static llama/ggml libraries; no CUDA/Vulkan/Metal/RPC backend; bounded -j4',
                                'permissions': 'read-only executable; runtime mounts only pinned executable/model descriptors'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('component', choices=['qemu', 'qemu-firmware', 'kali', 'model', 'llama'])
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--cmake', type=Path)
    parser.add_argument('--ninja', type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run unprivileged; this tool never installs system packages')
    if args.directory.is_symlink():
        parser.error('asset directory must not be a symlink')
    root = args.directory.absolute()
    os.umask(0o077)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    (root / 'home').mkdir(mode=0o700, exist_ok=True)
    if args.component == 'qemu-firmware':
        qemu_firmware(root)
        print(f'PACKAGED QEMU firmware: {root / "runtime.json"}', flush=True)
        return
    if (root / 'receipt.json').exists():
        parser.error('completed acquisition exists; use its pinned receipt, not a fresh moving resolution')
    if args.component == 'llama':
        if not args.cmake or not args.ninja:
            parser.error('llama build requires explicitly supplied CMake and Ninja binaries')
        llama(root, args.cmake.absolute(), args.ninja.absolute())
    else:
        {'qemu': qemu, 'kali': kali, 'model': model}[args.component](root)
    print(f'ACQUIRED {args.component}: {root / "receipt.json"}', flush=True)


if __name__ == '__main__':
    main()
