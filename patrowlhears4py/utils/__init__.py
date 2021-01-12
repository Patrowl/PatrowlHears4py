import click
import re
from pkg_resources import parse_version


def is_vulnerable_version(current_version, affected_versions, patched_versions):
    click.echo('----------- cv: %s, av: %s, pv: %s' % (current_version, affected_versions, patched_versions))
    if current_version == '':
        click.echo('Version not set. Unable to check vulnerabilities.')
        return False
    is_vulnerable = False

    if affected_versions == '*':
        return True

    if affected_versions != '' and len(re.split(', ', affected_versions)) == 1:
        av = re.split(', ', affected_versions)[0]
        # click.echo(av)
        cmp_ind = av.split(' ')[0]
        cmp_version = av.split(' ')[1]

        if cmp_version == '*':
            is_vulnerable = True
        elif cmp_ind == '<':
            is_vulnerable = parse_version(current_version) < parse_version(cmp_version)
        elif cmp_ind == '<=':
            is_vulnerable = parse_version(current_version) <= parse_version(cmp_version)
        elif cmp_ind == '>':
            is_vulnerable = parse_version(current_version) > parse_version(cmp_version)
        elif cmp_ind == '>=':
            is_vulnerable = parse_version(current_version) >= parse_version(cmp_version)

        if is_vulnerable:
            return True

    if patched_versions != '' and len(re.split(', ', patched_versions)) == 1:
        pv = re.split(', ', patched_versions)[0]
        click.echo('--> %s' % pv)

        if len(pv.split(' ')) == 1:
            is_vulnerable = parse_version(current_version) < parse_version(pv)
        else:
            cmp_ind = pv.split(' ')[0]
            cmp_version = pv.split(' ')[1]

            if cmp_ind == '<=':
                is_vulnerable = parse_version(current_version) > parse_version(cmp_version)
            elif cmp_ind == '>=':
                is_vulnerable = parse_version(current_version) < parse_version(cmp_version)

        # if is_vulnerable:
        #     return True

    click.echo('-----------')
    return is_vulnerable
