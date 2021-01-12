import click
# from patrowlhears4py.utils import is_vulnerable_version

def print_vuln(vuln, hears_api, vuln_cnt, base_url):
    click.echo('--- Vuln %s ---' % vuln_cnt)
    click.echo('PatrowlHears ID: %s (%s)' % (vuln['id'], '{}/#/vulns/{}'.format(base_url, vuln['id'])))
    click.echo('CVE: %s' % vuln['cveid'])
    click.echo('Summary: %s' % vuln['summary'])
    # if vuln['cwe_id'] != '':
    #     click.echo('CWE: %s - %s' % (vuln['cwe_id'], vuln['cwe_name']))
    click.echo('CVSSv2: %s - %s' % (vuln['cvss'], vuln['cvss_vector']))
    click.echo('CVSSv3: %s - %s' % (vuln['cvss3'], vuln['cvss3_vector']))
    click.echo('Score: %s/100' % vuln['score'])
    click.echo('Is exploitable: %s' % vuln['is_exploitable'])
    if vuln['is_exploitable'] is True:
        click.echo('Known exploits:')
        res_exploits = hears_api.get_vuln_exploits(vuln['id'])
        for exploit in res_exploits:
            click.echo(' - %s (%s)' % (exploit['link'], exploit['published']))


def print_package(package, hears_api, packages_cnt, base_url, current_version=''):
    click.echo('--- Package %s ---' % packages_cnt)
    click.echo('PatrowlHears ID: %s (%s)' % (package['id'], '{}/#/packages/{}'.format(base_url, package['id'])))
    click.echo('Name: %s' % package['name'])
    click.echo('Type: %s' % package['type'])

    vuln_cnt = 0
    for vuln in package['vulns']:
        vuln_cnt += 1
        print_vuln(vuln, hears_api, '%s/%s' % (vuln_cnt, len(package['vulns'])), base_url)
        click.echo('Affected versions:')
        for v in vuln['vulnerable_packages_versions'][package['type']][package['name']]:
            if 'affected_versions' in v.keys() and 'patched_versions' in v.keys():
                click.echo('- %s (patched in %s)' % (v['affected_versions'], v['patched_versions']))

                # click.echo(is_vulnerable_version(
                #     current_version=current_version,
                #     affected_versions=v['affected_versions'],
                #     patched_versions=v['patched_versions'],
                # ))

    click.echo('\n')
