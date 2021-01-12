import click
import os


# pip packages
def extract_pip_packages(package_file):
    packages = {}
    if os.path.exists(package_file) is False:
        click.echo('File not found: %s' % package_file)
        return packages

    with open(package_file, 'rb') as f:
        try:
            content = f.readlines()
        except Exception as e:
            click.echo('Error with file %s: %s' % (package_file, e))

    content = [x.strip().decode("utf-8") for x in content]
    click.echo(content)
    for package in content:
        if package.startswith('#'):
            continue

    return packages


def extract_installed_pip_packages():
    import pkg_resources
    installed_packages = pkg_resources.working_set
    return sorted(["%s==%s" % (i.key, i.version) for i in installed_packages])
