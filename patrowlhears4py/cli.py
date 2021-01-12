# import sys
import click
import re
from patrowlhears4py.api import PatrowlHearsApi
from patrowlhears4py.utils.print import print_vuln, print_package
from patrowlhears4py.utils.pip import extract_pip_packages, extract_installed_pip_packages


@click.group()
@click.version_option("1.2.0")
def main():
    """CLI for PatrowlHears"""
    pass


@main.command()
@click.option('--url', '-u', required=True, type=str)
@click.option('--auth-token', '-t', required=True, type=str)
@click.option('--cve', required=False, type=str)
@click.option('--cpe', required=False, type=str)
@click.argument('keyword', required=False)
def search(**kwargs):
    """Search through Vuln Database for vulnerabilities and exploits"""
    # click.echo(kwargs)

    hears_api = PatrowlHearsApi(url=kwargs['url'], auth_token=kwargs['auth_token'])
    if kwargs['keyword'] is not None:
        search_vulns_args = {'search': kwargs['keyword']}
    elif kwargs['cve'] is not None:
        search_vulns_args = {'cveid': kwargs['cve'].upper()}
    elif kwargs['cpe'] is not None:
        search_vulns_args = {'cpe': kwargs['cpe'].lower()}
    else:
        click.echo('Missing args "keyword" ')
        return

    search_vulns_args.update({'page': 1})
    has_next = True
    vuln_cnt = 0
    while has_next:
        res = hears_api.search_vulns(**search_vulns_args)

        for vuln in res['results']:
            vuln_cnt += 1
            print_vuln(vuln, hears_api, '%s/%s' % (vuln_cnt, res['count']), kwargs['url'])

        if res['next'] is None:
            has_next = False
        search_vulns_args.update({'page': search_vulns_args['page']+1})


@main.command()
@click.option('--url', '-u', required=True, type=str)
@click.option('--auth-token', '-t', required=True, type=str)
@click.option('--type', required=True, type=str)  # pip, npm, maven, ...
@click.option('--file', required=False, type=str)
@click.argument('name', required=False)
def scan(**kwargs):
    """Scan packages"""
    # click.echo(kwargs)

    hears_api = PatrowlHearsApi(url=kwargs['url'], auth_token=kwargs['auth_token'])

    if kwargs['name'] is None:
        # Extract local packages
        if kwargs['type'] is not None and kwargs['type'].lower() == 'pip':
            packages = extract_installed_pip_packages()
            click.echo(packages)
            for package in packages:
                search_package_vulns_args = {'page': 1, 'type': 'pip', 'name': re.split('=|<|>', package)[0]}
                current_version = re.split('=|<|>', package)[-1]
                has_next = True
                packages_cnt = 0
                while has_next:
                    res = hears_api.get_packages(**search_package_vulns_args)

                    for package_res in res['results']:
                        packages_cnt += 1
                        print_package(package_res, hears_api, '', kwargs['url'], current_version)

                    if res['next'] is None:
                        has_next = False
                    search_package_vulns_args.update({'page': search_package_vulns_args['page']+1})
        return

    search_package_vulns_args = {'page': 1}
    if kwargs['type'] is not None:
        search_package_vulns_args.update({'type': kwargs['type'].lower()})
    if kwargs['name'] is not None:

        search_package_vulns_args.update({'name': re.split('=|<|>', kwargs['name'].lower())[0]})

    if kwargs['file'] is None and kwargs['name'] is not None:
        has_next = True
        packages_cnt = 0
        current_version = re.split('=|<|>', kwargs['name'].lower())[-1]
        while has_next:
            res = hears_api.get_packages(**search_package_vulns_args)

            for package in res['results']:
                packages_cnt += 1
                print_package(package, hears_api, '%s/%s' % (packages_cnt, res['count']), kwargs['url'], current_version)

            if res['next'] is None:
                has_next = False
            search_package_vulns_args.update({'page': search_package_vulns_args['page']+1})
        return

    else:
        if kwargs['type'] is not None and kwargs['type'].lower() == 'pip':
            packages = extract_pip_packages(kwargs['file'])
            click.echo(packages)


if __name__ == '__main__':
    main(prog_name="hears")
