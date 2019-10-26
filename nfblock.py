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
__updated__ = '2019-10-26'

NFT_PATH = '/usr/sbin/nft'
RE_IP = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'


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
    p2p_re = re.compile(r'(?P<name>.+):(?P<range_start>' + RE_IP + ')'
                        r'-(?P<range_end>' + RE_IP + ')$')

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
'''

    # Setup argument parser
    parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--download", dest="download", action="store_true", help="download the blocklist")
    parser.add_argument("-l", "--list-stats", dest="list_stats", action="store_true", help="list the hit sattistics")
    parser.add_argument("-b", "--blocklist", dest="blocklist", help="blocklists to download  [default: %(default)s]", default=['bt_level1'])
    parser.add_argument("-f", "--family", dest="family", help="name of the netfilter family  [default: %(default)s]", default='inet')
    parser.add_argument("-t", "--table", dest="table", help="name of the netfilter table  [default: %(default)s]", default='filter')
    parser.add_argument("-s", "--set", dest="set", help="name of the blocklist set  [default: %(default)s]", default='blocklist')
    parser.add_argument("-c", "--counter-map", dest="counter_map", help="name of the blocklist counter map [default: %(default)s]")
    parser.add_argument("-o", "--output-file", dest="output_file", help="output file path  [default: %(default)s]", default='/var/lib/nfblock/nfblock.nft')
    parser.add_argument("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %(default)s]")
    parser.add_argument('-V', '--version', action='version', version=program_version_message)

    # Process arguments
    args = parser.parse_args()

    output_file = args.output_file
    blocklist = args.blocklist
    verbose = args.verbose
    family_name = args.family
    table_name = args.table
    set_name = args.set
    counter_map_name = args.counter_map

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

                ostream.write(f'add element {family_name} {table_name} {set_name} ')
                if s != e:
                    ostream.write(f'{{ {s}-{e} }} # {n} \n')
                else:
                    ostream.write(f'{{ {s} }} # {n}\n')

                if counter_map_name is not None:
                    ostream.write(f'add counter {family_name} {table_name} {s}\n')
                    ostream.write(f'add element {family_name} {table_name} {counter_map_name} ')
                    if s != e:
                        ostream.write(f'{{ {s}-{e} : {s} }}\n')
                    else:
                        ostream.write(f'{{ {s} : {s} }}\n')

        return 0

    if args.list_stats:
        addr_map = {}

        with open(output_file) as stream:
            nft_re = re.compile(
                r'add element (?P<family>\S+) (?P<range>\S+) (?P<set>\S+) '
                r'{ (?P<range_start>' + RE_IP + ')'
                r'(?:-(?P<range_end>' + RE_IP + '))? } '
                r'# (?P<name>.*)$')

            for l in stream:
                r = nft_re.match(l);
                if r:
                    e = r.group('range_end') or r.group('range_start')
                    addr_map[r.group('range_start')] = (e, r.group('name').strip())

        res = subprocess.run([NFT_PATH, '--json', 'list', 'table', family_name, table_name],
                             capture_output=True)
        res.check_returncode()

        nft_output = json.loads(res.stdout)

        logging.warning('Blocklist hit statistics:')

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
            logging.warning(f"{counter['name']}-{info[0]} {info[1]} "
                            f"packets: {counter['packets']} bytes: {counter['bytes']}")

        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
