"""aws-misconf: busca configuraciones incorrectas en una cuenta de AWS usando las reglas de rules/."""
import botocore.session
import click
from botocore.exceptions import BotoCoreError, ClientError
from jmespath.exceptions import JMESPathError

from engine import RISKS, filter_rules, load_rules, run_rule

DEFAULT_REGION = "us-east-1"
RISK_COLORS = {"low": "green", "mid": "yellow", "high": "red", "critical": "magenta"}


def create_session(profile, access_key, secret_key):
    """Crea una sesión de botocore con un perfil o con access key/secret key."""
    if profile and (access_key or secret_key):
        raise click.UsageError("Usa --profile o --access_key/--secret_key, no ambos.")
    if bool(access_key) != bool(secret_key):
        raise click.UsageError("--access_key y --secret_key deben usarse juntos.")

    session = botocore.session.Session(profile=profile)
    if access_key:
        session.set_credentials(access_key, secret_key)
    return session


def authenticate(session, region):
    """Valida las credenciales con STS. Devuelve la región efectiva y la identidad de la cuenta."""
    try:
        region = region or session.get_config_variable("region") or DEFAULT_REGION
        identity = session.create_client("sts", region_name=region).get_caller_identity()
    except BotoCoreError as e:  # perfil inexistente, credenciales ausentes...
        raise click.ClickException(f"No se pudo crear la sesión de AWS: {e}")
    except ClientError as e:  # AWS rechazó las credenciales
        raise click.ClickException(f"AWS rechazó las credenciales: {e}")
    return region, identity


def print_result(rule, rows):
    """Muestra la cabecera de la regla y una tabla con sus hallazgos."""
    color = RISK_COLORS[rule["risk"]] if rows else "green"
    click.secho(f"[{rule['risk'].upper()}] {rule['id']} - {rule['name']}", fg=color, bold=True)
    if not rows:
        click.secho("  Sin hallazgos\n", fg="green")
        return

    headers = list(rule["columns"])
    table = [["-" if row[h] is None else str(row[h]) for h in headers] for row in rows]
    widths = [max([len(header)] + [len(line[i]) for line in table]) for i, header in enumerate(headers)]

    click.echo("  " + "  ".join(header.ljust(width) for header, width in zip(headers, widths)))
    for line in table:
        click.echo("  " + "  ".join(value.ljust(width) for value, width in zip(line, widths)))
    click.echo(f"  {len(rows)} hallazgo(s)\n")


@click.command()
@click.option("--profile", help="Perfil de ~/.aws/credentials.")
@click.option("--access_key", help="Access key ID de AWS (alternativa a --profile).")
@click.option("--secret_key", help="Secret access key de AWS (usar junto con --access_key).")
@click.option("--region", help=f"Región a analizar. Por defecto, la del perfil o {DEFAULT_REGION}.")
@click.option("--risk", type=click.Choice(RISKS), help="Riesgo mínimo: ejecuta esa criticidad y las superiores.")
@click.option("--rule", "rule_ids", multiple=True, metavar="ID", help="Ejecuta solo esta regla. Repetible.")
def main(profile, access_key, secret_key, region, risk, rule_ids):
    """Busca configuraciones incorrectas en una cuenta de AWS usando las reglas de rules/."""
    session = create_session(profile, access_key, secret_key)

    try:
        rules = filter_rules(load_rules(), risk=risk, rule_ids=rule_ids)
    except ValueError as e:
        raise click.ClickException(str(e))
    if not rules:
        click.echo("Ninguna regla cumple los filtros indicados.")
        return

    region, identity = authenticate(session, region)
    click.echo(f"Cuenta {identity['Account']} ({identity['Arn']}) - región {region}\n")

    findings = errors = 0
    for rule in rules:
        try:
            client = session.create_client(rule["service"], region_name=region)
            rows = run_rule(client, rule)
        except (BotoCoreError, ClientError, JMESPathError, ValueError) as e:
            click.secho(f"[error] {rule['id']}: {e}\n", fg="red")
            errors += 1
            continue
        print_result(rule, rows)
        findings += len(rows)

    click.echo(f"Resumen: {len(rules)} regla(s), {findings} hallazgo(s), {errors} error(es)")


if __name__ == "__main__":
    main()
