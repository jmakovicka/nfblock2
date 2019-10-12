#!/usr/bin/python3
# encoding: utf-8

'''
nfblock -- nftables blocklist downloader & converter

@author:     Jindrich Makovicka

@copyright:  2019 Jindrich Makovicka. All rights reserved.

@license:    Apache License 2.0

@contact:    makovick@gmail.com
'''

import sys
import gzip
import re
import logging
import json
import subprocess
from urllib import request

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = 0.1
__date__ = '2019-09-29'
__updated__ = '2019-10-12'

NFT_PATH = '/usr/sbin/nft'


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''

    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = f"E: {msg}"

    def __str__(self):
        return self.msg

    def __unicode__(self):
        return self.msg


def read_blocklist(name):
    logging.info(f'Loading blocklist: {name}')
    url = f'http://list.iblocklist.com/?list={name}&fileformat=p2p&archiveformat=gz'
    p2p_re = re.compile(r'(?P<name>.+):(?P<range_start>(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+))'
                        r'-(?P<range_end>(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+))$')

    addr_list = []

    logging.debug(f'BLocklist URL: {url}')
    with gzip.open(request.urlopen(url), mode='rt', encoding='utf-8') as stream:
        for line in stream:
            line = line.strip()
            if line.startswith('#') or line == '':
                continue

            r = p2p_re.match(line)
            if r:
                addr_list.append((r.group('range_start'), r.group('range_end'), r.group('name')))
            else:
                raise CLIError('Parse error: ' + line)

    logging.info(f'Loaded {len(addr_list)} entries')
    return addr_list


def main(argv=None):  # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_version = f"v{__version__}"
    program_build_date = str(__updated__)
    program_version_message = f'%(prog)s {program_version} ({program_build_date})'
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = f'''{program_shortdesc}

USAGE
'''

    # Setup argument parser
    parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--download", dest="download", action="store_true", help="Download the blocklist")
    parser.add_argument("-l", "--list-stats", dest="list_stats", action="store_true", help="List the hit sattistics")
    parser.add_argument("-b", "--blocklist", dest="blocklist", help="Blocklists to download  [default: %(default)s]", default=['bt_level1'])
    parser.add_argument("-f", "--family", dest="family_name", help="Name of the netfilter family  [default: %(default)s]", default='inet')
    parser.add_argument("-t", "--table", dest="table_name", help="Name of the netfilter table  [default: %(default)s]", default='filter')
    parser.add_argument("-s", "--set", dest="set_name", help="Name of the blocklist set  [default: %(default)s]", default='blocklist')
    parser.add_argument("-c", "--counter-map-name", dest="counter_map_name", help="Name of the blocklist counter map [default: %(default)s]")
    parser.add_argument("-o", "--output-file", dest="output_file", help="Output file path  [default: %(default)s]", default='/var/lib/nfblock/nfblock.nft')
    parser.add_argument("-v", "--verbose", dest="verbose", action="count", help="Set verbosity level [default: %(default)s]")
    parser.add_argument('-V', '--version', action='version', version=program_version_message)

    # Process arguments
    args = parser.parse_args()

    output_file = args.output_file
    blocklist = args.blocklist
    verbose = args.verbose
    family_name = args.family_name
    table_name = args.table_name
    set_name = args.set_name
    counter_map_name = args.counter_map_name

    if verbose is None:
        log_level = logging.WARNING
    elif verbose >= 2:
        log_level = logging.DEBUG
    elif verbose >= 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(format='%(message)s', level=log_level)

    if args.download:
        addr_list = []

        for b in blocklist:
            addr_list += read_blocklist(b)

        logging.info(f'Writing nftables config: {output_file}')

        with open(output_file, mode='w') as ostream:
            ostream.write(f'flush set {family_name} {table_name} {set_name}\n')

            if counter_map_name is not None:
                ostream.write(f'flush map {family_name} {table_name} {counter_map_name}\n')

            for a in addr_list:
                s, e, n = a

                if s != e:
                    ostream.write(f'add element {family_name} {table_name} {set_name} {{ {s}-{e} }} # {n} \n')
                else:
                    ostream.write(f'add element {family_name} {table_name} {set_name} {{ {s} }} # {n}\n')

                if counter_map_name is not None:
                    ostream.write(f'add counter {family_name} {table_name} {s}\n')
                    if s != e:
                        ostream.write(f'add element {family_name} {table_name} {counter_map_name} {{ {s}-{e} : {s} }}\n')
                    else:
                        ostream.write(f'add element {family_name} {table_name} {counter_map_name} {{ {s} : {s} }}\n')

        return 0

    if args.list_stats:
        addr_map = {}

        with open(output_file) as stream:
            nft_re = re.compile(
                r'add element (?P<family>\S+) (?P<range>\S+) (?P<set>\S+) '
                r'{ (?P<range_start>(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+))'
                r'(?:-(?P<range_end>(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+)))? } '
                r'# (?P<name>.*)$')

            for l in stream:
                r = nft_re.match(l);
                if r:
                    e = r.group('range_end') or r.group('range_start')
                    addr_map[r.group('range_start')] = (e, r.group('name').strip())

        res = subprocess.run([NFT_PATH, '--json', 'list', 'table', 'inet', 'filter'], capture_output=True)
        res.check_returncode()

        nft_output = json.loads(res.stdout)

        print('Blocklist hit statistics:')

        hit_list = []

        for entry in nft_output['nftables']:
            if 'counter' in entry:
                counter = entry['counter']
                if counter['family'] == family_name and \
                   counter['table'] == table_name and \
                   counter['packets'] > 0:

                    hit_list.append(counter)

        hit_list.sort(key=lambda c: c['packets'], reverse=True)

        for counter in hit_list:
            info = addr_map.get(counter['name'], ('?', '(unknown)'))
            print(f"{counter['name']}-{info[0]}", info[1],
                  'packets:', counter['packets'],
                  'bytes:', counter['bytes'])

        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
