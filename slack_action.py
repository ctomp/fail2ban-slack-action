import argparse
import logging

import pycountry
import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('webhook_url', type=str)
    parser.add_argument('msg_type', type=str)
    parser.add_argument('jail', type=str)
    parser.add_argument('ip', type=str)
    parser.add_argument('failures', type=int)

    args = parser.parse_args()

    if args.msg_type == 'ban':
        msg = create_ban_msg(args)
    elif args.msg_type == 'unban':
        msg = f'Removed {args.ip} from jail {args.jail}'
    elif args.msg_type == 'start':
        msg = f'Jail \'{args.jail}\' has been started'
    elif args.msg_type == 'stop':
        msg = f'Jail \'{args.jail}\' has been stopped'
    else:
        # Should not happen, can restrict in args parser so this case won't matter
        msg = 'Unknown msg type'

    try:
        slack_response = requests.post(f'https://hooks.slack.com/services/{args.webhook_url}', json={
            "channel": "#alerts",
            "username": "fail2ban",
            "text": msg
        }, timeout=2)
        if slack_response.status_code != 200:
            slack_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.exception(e)


def create_ban_msg(args):
    failure_txt = "failures" if args.failures != 1 else "failure"

    # Fetch what country the IP hails from (for curiosity's sake)
    try:
        ipinfo_response = requests.get(f'https://ipinfo.io/{args.ip}/json', timeout=1)
        if ipinfo_response.status_code == 200:
            ip_json = ipinfo_response.json()
            if 'country' in ip_json:
                country_code = ip_json['country'].lower()
                try:
                    country = pycountry.countries.lookup(country_code)
                    return f'Banned :flag-{country_code}: {args.ip} ({country.name}) in jail {args.jail} for ' \
                           f'{args.failures} {failure_txt}'
                except LookupError:
                    return f'Banned :flag-{country_code}: {args.ip} (Unknown) in jail {args.jail} for ' \
                           f'{args.failures} {failure_txt}'
    except requests.exceptions.RequestException as e:
        logging.exception(e)

    return f'Banned {args.ip} (Unknown) in jail {args.jail} for {args.failures} {failure_txt}'


if __name__ == "__main__":
    main()
