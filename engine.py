"""Carga las reglas de rules/*.yaml y las ejecuta contra AWS con botocore."""
from pathlib import Path

import jmespath
import yaml
from jmespath.exceptions import JMESPathError

RULES_DIR = Path(__file__).resolve().parent / "rules"
RISKS = ["low", "mid", "high", "critical"]  # de menor a mayor criticidad
REQUIRED_FIELDS = ("id", "name", "description", "risk", "service", "operation", "query", "columns")


def load_rules(folder=RULES_DIR):
    """Lee y valida todas las reglas YAML de la carpeta. Lanza ValueError si alguna no es válida."""
    rules = []
    for path in sorted(Path(folder).glob("*.yaml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise ValueError(f"{path.name}: YAML no válido: {e}") from e
        _validate(rule, path.name)
        rules.append(rule)

    ids = [rule["id"] for rule in rules]
    duplicated = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicated:
        raise ValueError(f"IDs de regla duplicados: {', '.join(duplicated)}")
    return rules


def _validate(rule, filename):
    if not isinstance(rule, dict):
        raise ValueError(f"{filename}: el fichero debe contener un diccionario YAML")

    missing = [field for field in REQUIRED_FIELDS if field not in rule]
    if missing:
        raise ValueError(f"{filename}: faltan los campos {', '.join(missing)}")

    if rule["risk"] not in RISKS:
        raise ValueError(f"{filename}: risk '{rule['risk']}' no válido. Usa uno de: {', '.join(RISKS)}")

    if not isinstance(rule["columns"], dict) or not rule["columns"]:
        raise ValueError(f"{filename}: 'columns' debe ser un diccionario con al menos una columna")

    try:
        jmespath.compile(rule["query"])
        for expression in rule["columns"].values():
            jmespath.compile(expression)
    except JMESPathError as e:
        raise ValueError(f"{filename}: expresión JMESPath no válida: {e}") from e


def filter_rules(rules, risk=None, rule_ids=()):
    """Filtra por riesgo mínimo (incluye los superiores) y/o por ids concretos."""
    selected = rules

    if risk:
        minimum = RISKS.index(risk)
        selected = [rule for rule in selected if RISKS.index(rule["risk"]) >= minimum]

    if rule_ids:
        known = {rule["id"] for rule in rules}
        unknown = [rule_id for rule_id in rule_ids if rule_id not in known]
        if unknown:
            raise ValueError(f"Regla(s) desconocida(s): {', '.join(unknown)}")
        selected = [rule for rule in selected if rule["id"] in rule_ids]

    return selected


def run_rule(client, rule):
    """Ejecuta una regla con un cliente botocore y devuelve una fila (dict columna -> valor) por recurso."""
    operation = rule["operation"]
    if not hasattr(client, operation):
        raise ValueError(f"{rule['id']}: el servicio '{rule['service']}' no tiene la operación '{operation}'")

    params = rule.get("params") or {}
    if client.can_paginate(operation):
        response = client.get_paginator(operation).paginate(**params).build_full_result()
    else:
        response = getattr(client, operation)(**params)

    resources = jmespath.search(rule["query"], response)
    if not isinstance(resources, list):
        raise ValueError(f"{rule['id']}: la query debe devolver una lista de recursos")

    return [
        {column: jmespath.search(expression, resource) for column, expression in rule["columns"].items()}
        for resource in resources
    ]
