#!/usr/bin/env python3
#      __      __   _____
#     /\ \    / /  / ____|
#    /  \ \  / /  | |     __ _  ___  ___  __ _ _ __
#   / /\ \ \/ /   | |    / _` |/ _ \/ __|/ _` | '__|
#  / ____ \  /    | |___| (_| |  __/\__ \ (_| | |
# /_/    \_\/      \_____\__,_|\___||___/\__,_|_|
#
# Script to make request on the AVCaesar API

from math import ceil
import os
import argparse
import avcaesar_api
import configparser


def action_check(conn, args):
    for arg in args.check:
        data = conn.has_sample_hash(arg)
        if data:
            print("[+]", arg, "is in database")
        else:
            print("[+]", arg, "not in database")


def action_download(conn, args):
    for arg in args.download:
        print("[!] Downloading...")
        payload, filename = conn.download(arg)
        if payload:
            f = open(filename, "wb")
            f.write(payload)
            f.close()
            print("[+]", arg, "was saved successfully as: ", filename)
        else:
            print("[-]", arg, "does not exist in database.")


def action_history_analysis(conn, args):
    analysis_history = conn.history_analysis(private=args.private, page=args.page, per_page=args.per_page)
    print("[*] Total:", analysis_history['total'])
    if analysis_history['total']:
        print("[*] Page:  ", analysis_history['page'], "/",
              ceil(analysis_history['total']/float(analysis_history['per_page'])), sep='')
        for analysis in analysis_history['data']:
            print("#" * 40)
            print("[*] Date:       ", analysis['date'])
            if not analysis.get('deleted'):
                print("[*] Reference:  ", analysis['reference'])
                print("[*] MD5:        ", analysis['md5'])
                print("[*] SHA1:       ", analysis['sha1'])
            print("[*] SHA256:     ", analysis['sha256'])

    else:
        print("[!] The history is empty")


def action_info(conn, args):
    for arg in args.info:
        try:
            result = conn.info(arg, args.private)
            total_av = len(result['antivirus'])
            negatives = [av['result'] for av in result['antivirus']].count(None)
            print("[+] Sample", arg, "found")
            print("[*] Information:")
            print("SHA256: %s" % result['sha256'])
            print("SHA1: %s" % result['sha1'])
            print("MD5: %s" % result['md5'])
            print("Detection ratio: %s%s%s/%s%s%s" % (
                bcolors.RED, total_av - negatives,
                bcolors.ENDC,
                bcolors.YELLOW,
                total_av,
                bcolors.ENDC
            ))
            print("First seen: %s%s%s" % (
                bcolors.GREEN,
                result['first_seen'],
                bcolors.ENDC
            ))
            print("Last seen: %s%s%s" % (
                bcolors.GREEN,
                result['last_seen'],
                bcolors.ENDC
            ))
            print("Last update: %s%s%s" % (
                bcolors.GREEN,
                result['last_update'],
                bcolors.ENDC
            ))
            print("Type:", result.get('type', '-'))
            print("Size: %s%s%s" % (bcolors.YELLOW, result['size'], bcolors.ENDC))

            for av in result['antivirus']:
                av_result_display = ""

                if av['result'] is not None:
                    av_result_display += "%s: %s%s%s" % (av['name'], bcolors.RED, av['result'], bcolors.ENDC)
                else:
                    av_result_display += "%s: %s%s%s" % (av['name'], bcolors.GREEN, '-', bcolors.ENDC)

                if av['status'] in ['success', 'failure']:
                    print(av_result_display)
                elif av['status'] == 'rescan':
                    print("%s%s" % (av_result_display, " (%srescan in progress%s)" % (bcolors.YELLOW, bcolors.ENDC)))
                else:
                    print("%s: %s%s%s" % (av['name'], bcolors.YELLOW, 'In progress', bcolors.ENDC))
        except avcaesar_api.NotFoundException:
            print("[-] Sample", arg, "not found")


def action_is_authenticated(conn, args):
    result = conn.is_authenticated()
    print("[*] authenticated: %s" % result['authenticated'])
    print("[*] direct:        %s" % result['direct'])


def action_quota(conn, args):
    quotas = conn.quota()
    for service in quotas:
        print(
            "[*] Service:", service,
            "| current:", "%s%s%s" % (bcolors.YELLOW, quotas[service]['current'], bcolors.ENDC),
            "| limit:", "%s%s%s" % (bcolors.YELLOW, quotas[service]['limit'], bcolors.ENDC),
            "| timeout:", "%s%s%s" % (bcolors.YELLOW, quotas[service]['timeout'], bcolors.ENDC), "s"
        )


def action_remove(conn, args):
    for reference in args.remove:
        try:
            conn.delete(reference, private=args.private)
            print("[+] The", reference, "sample has been deleted.")
        except avcaesar_api.NotFoundException:
            print("[-] The", reference, "sample was not found.")


def action_update(conn, args):
    for reference in args.update:
        try:
            conn.update(reference)
            print("[+] A analysis has been scheduled for", reference, "sample.")
        except avcaesar_api.NotFoundException:
            print("[-] The", reference, "sample was not found.")
        except avcaesar_api.ResourceLockedException:
            print("[-] The", reference, "sample was locked.")


def action_upload(conn, args):
    for arg in args.upload:
        print("[!] Upload of", arg, "in process...")
        payload = open(arg, "rb")
        try:
            data = conn.upload(payload, private=args.private)
            resource_locked = False
        except avcaesar_api.ResourceLockedException as e:
            data = e.data
            resource_locked = True
        payload.close()
        if data:
            print("[+] Sample was successfully uploaded.")
            print("[*] Reference:   %s" % data['reference'])
            print("[*] MD5:         %s" % data['md5'])
            print("[*] SHA1:        %s" % data['sha1'])
            print("[*] SHA256:      %s" % data['sha256'])
            if not args.private:
                print("[*] Is new?:     %s" % data['new'])
                print("[*] Is locked?: ", resource_locked)
        else:
            print("Upload failed: %s (status code: %s)" % (data.content, data.status_code))


class bcolors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'

    def disable(self):
        self.GREEN = ''
        self.RED = ''
        self.YELLOW = ''
        self.ENDC = ''


def main():
    # Load user configuration
    config = configparser.ConfigParser()
    # Priority:  ./avcaesar_api.cfg > ~/.avcaesar_api.cfg
    config.read(
        [
            os.path.join(os.path.expanduser("~"), ".avcaesar_api.cfg"),
            os.path.join(os.curdir, "avcaesar_api.cfg")
        ]
    )
    parser = argparse.ArgumentParser(description="AVCaesar API tools")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-c', '--check',
        nargs="+",
        dest="check",
        metavar="hash",
        help="Check a hash."
    )
    group.add_argument(
        '-u', '--upload',
        nargs="+",
        dest="upload",
        metavar="file",
        help="Upload a sample."
    )
    group.add_argument(
        '-d', '--download',
        nargs="+",
        dest="download",
        metavar="reference",
        help="Download a sample. (Only in public mode)"
    )
    group.add_argument(
        '-i', '--info',
        nargs="+",
        dest="info",
        metavar="reference",
        help="Show sample info."
    )
    group.add_argument(
        '--update',
        nargs="+",
        dest="update",
        metavar="reference",
        help="Rescan a sample. (Only in public mode)"
    )
    group.add_argument(
        '-r', '--remove',
        nargs="+",
        dest="remove",
        metavar="reference",
        help="Remote a sample. (Only in private mode)"
    )
    group.add_argument(
        '--analysis-history',
        dest="action",
        action='store_const',
        const="analysis_history",
        help="Show your analysis history."
    )
    group.add_argument(
        '--is-authenticated',
        dest="action",
        action='store_const',
        const="is_authenticated",
        help="Check your authentication"
    )
    group.add_argument(
        '--quota',
        dest="action",
        action='store_const',
        const="quota",
        help="Show your quota."
    )
    parser.add_argument(
        '--private',
        dest='private',
        action='store_true',
        help="Activate mode private.",
        default=False
    )
    parser.add_argument(
        '--page',
        dest='page',
        action='store',
        help="Specify the desired page.",
        default=1
    )
    parser.add_argument(
        '--per-page',
        dest='per_page',
        action='store',
        help="Specify the desired limit per page.",
        default=5
    )
    parser.add_argument(
        '--api-key',
        action="store",
        help="Specify the api key.",
        default=config.get("api", "key", fallback=None)
    )
    parser.add_argument(
        '--api-url',
        action="store",
        help="Specify the api url.",
        default=config.get("api", "url", fallback=avcaesar_api.config_malware_lu['url'])
    )
    parser.add_argument(
        '--api-server-cert',
        action="store",
        help="Specify the api server cert.",
        default=config.get("api", "server_cert", fallback=avcaesar_api.config_malware_lu['server_cert'])
    )
    parser.add_argument(
        '--version',
        action='version',
        version="%(prog)s {}".format(avcaesar_api.__version__)
    )

    args = parser.parse_args()
    conn = avcaesar_api.Connector(key=args.api_key, url=args.api_url, server_cert=args.api_server_cert)

    if args.check:
        action_check(conn, args)
    elif args.download:
        action_download(conn, args)
    elif args.upload:
        action_upload(conn, args)
    elif args.info:
        action_info(conn, args)
    elif args.action == "quota":
        action_quota(conn, args)
    elif args.action == "is_authenticated":
        action_is_authenticated(conn, args)
    elif args.action == "analysis_history":
        action_history_analysis(conn, args)
    elif args.update:
        action_update(conn, args)
    elif args.remove:
        action_remove(conn, args)


if __name__ == '__main__':
    main()
