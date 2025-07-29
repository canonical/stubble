#!/usr/bin/python
# SPDX-License-Identifier: 0BSD

from uuid import UUID
from pathlib import Path
from typing import *
import re
import json
import sys

guid_regexp = re.compile(r'\{[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}\}', re.I)

def parse_hwid_file(hwid_file: Path, inpath: Path, outpath: Path) -> None:
    content = hwid_file.open().readlines()

    data: dict[str, str] = {
        'Manufacturer': '',
        'Family': '',
        'Compatible': 'FIXME!',
    }
    guids: list[UUID] = []

    for line in content:
        for k in data:
            if line.startswith(k):
                data[k] = line.split(':')[1].strip()
                break
        else:
            guid = guid_regexp.match(line)
            if guid is not None:
                guids.append(UUID(guid.group(0)[1:-1]))

    for k, v in data.items():
        if not v:
            raise ValueError(f'hwid description file "{hwid_file}" does not contain "{k}"')

    name = data['Manufacturer'] + ' ' + data['Family']
    compatible = data['Compatible']

    device = {
        'type': 'devicetree',
        'name': name,
        'compatible': compatible,
        'hwids': guids,
    }

    with open(str(outpath / hwid_file.relative_to(inpath).with_suffix('.json')), 'w', encoding='utf-8') as f:
        json.dump(device, f, ensure_ascii=False, indent=4, default=str)

def parse_hwid_dir(inpath: Path, outpath: Path) -> None:
    hwid_files = inpath.rglob('*.txt')

    for hwid_file in hwid_files:
        parse_hwid_file(hwid_file, inpath, outpath)


inpath = Path('./hwids')
outpath = Path('./json')

if len(sys.argv) > 1:
    inpath = Path(sys.argv[1])

if len(sys.argv) > 2:
    outpath = Path(sys.argv[2])

parse_hwid_dir(inpath, outpath)
