#!/usr/bin/env python3
"""Register GNS3 qemu templates for appliance images already on the server.

rebuild_lab.py's preflight refuses to create templates on purpose: it cannot
recreate a disk image, so it fails loudly and tells the operator to import one.
This script is the other half of that - once the qcow2 IS on the server, it
turns lab/images.yaml into real templates without a GUI round trip.

It never downloads anything. Appliance images (vJunos, PAN-OS) are licensed and
distributed only through the vendor's own portal behind an account login, so
fetching one is a human step. What this does is verify what landed and wire it
up:

    1. ask the GNS3 server which qemu images it can see
    2. match them against lab/images.yaml
    3. check size and md5 against the server's own report, so a truncated or
       corrupted image is caught before it becomes a mystery boot hang
    4. create any template that is missing

Getting an image onto the server, once downloaded from the vendor portal.
Either scp it, or POST it through the API (no SSH client needed, and the
server hashes it on arrival):

    curl -X POST -T <image>.qcow2 \\
        http://<server>/v2/computes/local/qemu/images/<image>.qcow2

Usage:
    python lab/register_templates.py              # report what is present/missing
    python lab/register_templates.py --create     # create the missing templates
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGES_PATH = os.path.join(HERE, 'images.yaml')
TOPOLOGY_PATH = os.path.join(HERE, 'topology.yaml')

# Keys in an images.yaml entry that are not template properties and must be
# stripped before POSTing. "images" is our own image list. "kvm" is real, but
# it belongs to the .gns3a appliance format, not the template API - the server
# rejects the whole request with a 400 if it is passed through. It stays in
# images.yaml because "this needs nested virtualisation" is worth recording.
NON_TEMPLATE_KEYS = {'images', 'kvm'}

# Where the GNS3 VM keeps qemu disk images. Only used in operator hints.
IMAGE_DIR = '/opt/gns3/images/QEMU'


class RegisterError(Exception):
    """Something the operator has to look at, raised with the fix in the text."""


def step(msg):
    print(f'\n== {msg}')


def ok(msg):
    print(f'  [ok] {msg}')


def warn(msg):
    print(f'  [--] {msg}')


class Gns3Api:
    """Minimal GNS3 v2 REST client - stdlib only, same as rebuild_lab.py."""

    def __init__(self, base):
        self.base = base.rstrip('/') + '/v2'

    def _request(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f'{self.base}{path}', data=data, method=method,
            headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors='replace')
            raise RegisterError(f'{method} {path} failed: {error.code} {detail}')
        except urllib.error.URLError as error:
            raise RegisterError(
                f'Cannot reach the GNS3 server at {self.base}: {error.reason}\n'
                'Is the GNS3 VM running, and does lab/topology.yaml carry its '
                'address?')

    def get(self, path):
        return self._request('GET', path)

    def post(self, path, payload):
        return self._request('POST', path, payload)


def load_yaml(path):
    with open(path, encoding='utf-8') as handle:
        return yaml.safe_load(handle)


def server_images(api):
    """Filename -> what the server reports about it (filesize, md5sum).

    GNS3 hashes an image on upload and hands the md5 back in this listing, so
    integrity can be checked against the copy the hypervisor will actually
    boot without anyone shelling into the server or re-reading 4 GB.
    """
    return {image['filename']: image
            for image in api.get('/computes/local/qemu/images')}


def pick_image(spec, present):
    """First declared image that is actually on the server, and what it reports."""
    for candidate in spec['images']:
        if candidate['filename'] in present:
            return candidate, present[candidate['filename']]
    return None, None


def verify(image, reported):
    """Check the server's copy against what lab/images.yaml declares.

    Both halves matter and fail differently: a size mismatch is a truncated or
    wrong-release download, while a size match with a bad md5 is corruption in
    transit. Either one boots into a hang that looks like a broken image, so
    they are worth catching here rather than on the console at 2am.
    """
    expected_size = image.get('filesize')
    actual_size = reported.get('filesize', 0)
    if expected_size and actual_size != expected_size:
        raise RegisterError(
            f'{image["filename"]} is {actual_size} bytes on the server, '
            f'expected {expected_size}. The image is truncated, or is not the '
            'release lab/images.yaml describes - re-upload it before importing.')
    if expected_size:
        ok(f'size matches ({actual_size} bytes)')

    expected_md5 = image.get('md5')
    actual_md5 = reported.get('md5sum')
    if expected_md5 and actual_md5 and actual_md5 != expected_md5:
        raise RegisterError(
            f'{image["filename"]} hashes to {actual_md5} on the server, '
            f'expected {expected_md5}. The upload corrupted in transit, or the '
            'file is not the one lab/images.yaml describes - re-upload it.')
    if expected_md5 and actual_md5:
        ok(f'md5 matches ({actual_md5})')
    elif expected_md5:
        warn('server reported no md5 - integrity not checked')


def build_payload(name, spec, image_filename):
    """An images.yaml entry becomes a GNS3 template creation payload."""
    payload = {key: value for key, value in spec.items()
               if key not in NON_TEMPLATE_KEYS}
    payload['name'] = name
    payload['compute_id'] = 'local'
    payload['hda_disk_image'] = image_filename
    return payload


def register(api, name, spec, existing, present, args):
    """Returns True if the template still needs a disk image."""
    step(f'template "{name}"')
    if name in existing:
        ok('already registered')
        return False

    image, reported = pick_image(spec, present)
    if image is None:
        wanted = ', '.join(candidate['filename'] for candidate in spec['images'])
        warn(f'no disk image on the server. Expected one of: {wanted}')
        return True

    ok(f'found {image["filename"]}')
    verify(image, reported)

    if not args.create:
        warn('not registered (re-run with --create)')
        return False

    api.post('/templates', build_payload(name, spec, image['filename']))
    ok(f'created template "{name}" ({spec["ram"]} MB RAM, {spec["cpus"]} vCPU)')
    return False


def main():
    parser = argparse.ArgumentParser(
        description='Register GNS3 templates for images already on the server.')
    parser.add_argument('--create', action='store_true',
                        help='create missing templates (default: report only)')
    parser.add_argument('--server', default=None,
                        help='GNS3 base URL (default: from lab/topology.yaml)')
    args = parser.parse_args()

    server = args.server or load_yaml(TOPOLOGY_PATH)['gns3']['server']
    api = Gns3Api(server)

    step(f'GNS3 server at {server}')
    ok(f'version {api.get("/version")["version"]}')

    declared = load_yaml(IMAGES_PATH)['templates']
    existing = {template['name'] for template in api.get('/templates')}
    present = server_images(api)

    needs_image = [name for name, spec in declared.items()
                   if register(api, name, spec, existing, present, args)]

    if needs_image:
        step('images still needed')
        for name in needs_image:
            print(f'  {name}: download from the vendor portal, then')
            print(f'    scp <image>.qcow2 gns3@<server>:{IMAGE_DIR}/')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except RegisterError as error:
        print(f'\nERROR: {error}', file=sys.stderr)
        sys.exit(1)
