"""Chequeos en Python para reglas que no caben en una sola operación + query JMESPath.

Una regla YAML con el campo `check: <nombre>` ejecuta la función registrada con ese nombre.
Cada chequeo recibe la sesión de botocore y los `params` de la regla (dict, puede estar vacío) y devuelve una lista de recursos (dicts); las
`columns` de la regla se aplican a esos dicts igual que en las reglas con `operation`.
"""
import csv
import io
import json
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from botocore.exceptions import ClientError

PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
READ_PERMISSIONS = {"READ", "FULL_CONTROL"}  # permisos de ACL que permiten leer el contenido
DEFAULT_REGION = "us-east-1"


def _optional(call, *missing_codes, **kwargs):
    """Ejecuta call y devuelve None si AWS responde con alguno de los códigos 'no configurado'."""
    try:
        return call(**kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] in missing_codes:
            return None
        raise


def _bucket_region(client, bucket):
    if bucket.get("BucketRegion"):
        return bucket["BucketRegion"]
    # Respuesta sin BucketRegion (botocore antiguo): get_bucket_location devuelve None para us-east-1 y "EU" para eu-west-1.
    location = client.get_bucket_location(Bucket=bucket["Name"]).get("LocationConstraint")
    return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(location, location)


def _buckets_by_region(session):
    """Lista los buckets de la cuenta (ListBuckets es global) agrupados por la región en la que viven."""
    client = session.create_client("s3", region_name=DEFAULT_REGION)
    if client.can_paginate("list_buckets"):
        buckets = client.get_paginator("list_buckets").paginate().build_full_result().get("Buckets", [])
    else:
        buckets = client.list_buckets().get("Buckets", [])

    by_region = {}
    for bucket in buckets:
        by_region.setdefault(_bucket_region(client, bucket), []).append(bucket["Name"])
    return by_region


def _inspect_bucket(client, name):
    """Recoge la configuración de acceso público de un bucket."""
    block = _optional(client.get_public_access_block, "NoSuchPublicAccessBlockConfiguration", Bucket=name)
    block = (block or {}).get("PublicAccessBlockConfiguration", {})
    status = _optional(client.get_bucket_policy_status, "NoSuchBucketPolicy", Bucket=name)
    grants = client.get_bucket_acl(Bucket=name).get("Grants", [])
    public_permissions = sorted(
        grant["Permission"] for grant in grants if grant.get("Grantee", {}).get("URI") in PUBLIC_GROUPS
    )
    return {
        "block": block,
        "policy_public": bool(status and status["PolicyStatus"].get("IsPublic")),
        "acl_permissions": public_permissions,
    }


def _scan_buckets(session):
    """Devuelve (bucket, región, configuración de acceso público) de todos los buckets de todas las regiones."""
    for region, names in sorted(_buckets_by_region(session).items()):
        client = session.create_client("s3", region_name=region)
        for name in sorted(names):
            try:
                yield name, region, _inspect_bucket(client, name)
            except ClientError as e:
                raise ValueError(f"bucket {name} ({region}): {e}") from e


def s3_bucket_exposed_content(session, params):
    """Buckets cuyo contenido puede leer cualquiera: política pública o ACL de lectura pública que sigan vigentes.

    Las opciones RestrictPublicBuckets e IgnorePublicAcls del Public Access Block del bucket
    anulan la política y las ACL públicas respectivamente. (No se consulta el bloqueo a nivel de cuenta.)
    """
    found = []
    for name, region, info in _scan_buckets(session):
        block = info["block"]
        public_policy = info["policy_public"] and not block.get("RestrictPublicBuckets")
        public_acl = bool(READ_PERMISSIONS & set(info["acl_permissions"])) and not block.get("IgnorePublicAcls")
        if public_policy or public_acl:
            found.append({"BucketId": name, "Region": region})
    return found


def s3_bucket_public_acl(session, params):
    """Buckets con una ACL que concede permisos a AllUsers o AuthenticatedUsers (esté o no bloqueada)."""
    return [
        {"BucketId": name, "Region": region, "Permissions": ", ".join(info["acl_permissions"])}
        for name, region, info in _scan_buckets(session)
        if info["acl_permissions"]
    ]


# --- IAM ---

AWS_POLICY_PREFIX = "arn:aws:iam::aws:policy/"
DEFAULT_ADMIN_POLICIES = ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess", "SecurityAudit"]
DEFAULT_ADMIN_THRESHOLD = 3


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _document(document):
    """botocore ya decodifica los documentos de política; si llega un string (URL-encoded), lo decodifica."""
    return json.loads(unquote(document)) if isinstance(document, str) else document or {}


def _is_admin_document(document):
    """True si algún Allow concede Action '*' o 'iam:*' sobre Resource '*'."""
    for statement in _as_list(_document(document).get("Statement")):
        if statement.get("Effect") != "Allow":
            continue
        if {"*", "iam:*"} & set(_as_list(statement.get("Action"))) and "*" in _as_list(statement.get("Resource")):
            return True
    return False


def _trusts_user(trust_policy, user_arn):
    """True si la trust policy permite al usuario (por ARN) asumir el rol."""
    for statement in _as_list(_document(trust_policy).get("Statement")):
        principal = statement.get("Principal")
        principals = _as_list(principal.get("AWS")) if isinstance(principal, dict) else []
        actions = {action.lower() for action in _as_list(statement.get("Action"))}
        if (statement.get("Effect") == "Allow" and user_arn in principals
                and actions & {"sts:assumerole", "sts:*", "*"}):
            return True
    return False


class _AdminPolicies:
    """Decide si una política gestionada o inline es administrativa."""

    def __init__(self, details, admin_names):
        self.admin_names = set(admin_names)
        self.managed = {}  # ARN -> es administrativa
        for policy in details.get("Policies", []):
            default = next((v for v in policy.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
            self.managed[policy["Arn"]] = bool(default) and _is_admin_document(default.get("Document"))

    def managed_is_admin(self, attached):
        arn = attached["PolicyArn"]
        if arn.startswith(AWS_POLICY_PREFIX) and attached["PolicyName"] in self.admin_names:
            return True
        return self.managed.get(arn, False)

    def admin_policies(self, entity, inline_key):
        """Políticas administrativas de un usuario/grupo/rol: lista de (clave única, nombre, tipo)."""
        found = [(item["PolicyArn"], item["PolicyName"], "managed")
                 for item in entity.get("AttachedManagedPolicies", []) if self.managed_is_admin(item)]
        found += [(("inline", entity["Arn"], item["PolicyName"]), item["PolicyName"], "inline")
                  for item in entity.get(inline_key, []) if _is_admin_document(item.get("PolicyDocument"))]
        return found


def iam_user_excess_admin_roles(session, params):
    """Usuarios con más de `threshold` asignaciones administrativas (directas, por grupo o por rol asumible)."""
    threshold = params.get("threshold", DEFAULT_ADMIN_THRESHOLD)
    iam = session.create_client("iam", region_name=DEFAULT_REGION)  # IAM es global
    details = iam.get_paginator("get_account_authorization_details").paginate().build_full_result()

    policies = _AdminPolicies(details, params.get("admin_policies", DEFAULT_ADMIN_POLICIES))
    groups = {group["GroupName"]: group for group in details.get("GroupDetailList", [])}
    admin_roles = [(role, policies.admin_policies(role, "RolePolicyList"))
                   for role in details.get("RoleDetailList", [])]
    admin_roles = [(role, found) for role, found in admin_roles if found]

    found_users = []
    for user in details.get("UserDetailList", []):
        assignments = {}  # clave única -> etiqueta; una asignación cuenta una vez aunque llegue por varias vías

        def add(found, via):
            for key, name, kind in found:
                label = f"{name} (inline)" if kind == "inline" and via is None else f"{name} ({via or 'directa'})"
                assignments.setdefault(key, label)

        add(policies.admin_policies(user, "UserPolicyList"), None)
        for group_name in user.get("GroupList", []):
            if group_name in groups:
                add(policies.admin_policies(groups[group_name], "GroupPolicyList"), f"grupo {group_name}")
        for role, _ in admin_roles:
            if _trusts_user(role.get("AssumeRolePolicyDocument"), user["Arn"]):
                assignments.setdefault(("role", role["Arn"]), f"{role['RoleName']} (rol)")

        if len(assignments) > threshold:
            found_users.append({
                "UserName": user["UserName"],
                "AdminCount": len(assignments),
                "AdminRoles": ", ".join(assignments.values()),
            })
    return found_users


DEFAULT_REPORT_TIMEOUT = 30  # segundos que se espera a que IAM genere el informe de credenciales
DEFAULT_REPORT_INTERVAL = 2
DEFAULT_MAX_AGE_DAYS = 365
DEFAULT_WARNING_DAYS = 15


def _credential_report(iam, timeout, interval):
    """Pide el informe de credenciales, espera a que esté listo y devuelve sus filas (dicts) ya leídas."""
    waited = 0
    while iam.generate_credential_report()["State"] != "COMPLETE":
        if waited >= timeout:
            raise ValueError(f"IAM no generó el informe de credenciales en {timeout} s")
        time.sleep(interval)
        waited += interval
    content = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def _load_credential_report(session, params):
    """Filas del informe de credenciales, con la espera y el tiempo máximo de los params de la regla."""
    iam = session.create_client("iam", region_name=DEFAULT_REGION)  # IAM es global
    return _credential_report(iam, params.get("report_timeout_seconds", DEFAULT_REPORT_TIMEOUT),
                              params.get("report_poll_interval_seconds", DEFAULT_REPORT_INTERVAL))


def _now():
    """Fecha actual en UTC. Único punto que lee el reloj, para poder fijarlo en los tests."""
    return datetime.now(timezone.utc)


def _parse_date(value):
    """Fecha del informe de credenciales, o None si no hay (N/A, no_information, vacío)."""
    if value in ("N/A", "no_information", "not_supported", ""):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iam_credentials_older_than(session, params):
    """Contraseñas de consola y access keys activas sin cambiar desde hace más de `max_age_days` días."""
    max_age = params.get("max_age_days", DEFAULT_MAX_AGE_DAYS)
    now = _now()

    found = []
    for row in _load_credential_report(session, params):
        # Contraseña: si nunca se cambió, cuenta desde la creación del usuario. La root (not_supported) no se revisa.
        credentials = []
        if row["password_enabled"] == "true":
            changed = row["password_last_changed"]
            credentials.append(("password", changed if _parse_date(changed) else row["user_creation_time"]))
        credentials += [(f"access_key_{n}", row[f"access_key_{n}_last_rotated"])
                        for n in (1, 2) if row[f"access_key_{n}_active"] == "true"]

        for credential, last_rotated in credentials:
            date = _parse_date(last_rotated)
            age = (now.date() - date.astimezone(timezone.utc).date()).days if date else None  # días de calendario UTC
            if age is not None and age > max_age:
                found.append({"UserName": row["user"], "Credential": credential,
                              "LastRotated": last_rotated, "AgeDays": age})
    return found


def iam_credentials_expiring_soon(session, params):
    """Contraseñas y access keys activas que caducan dentro de `warning_days` días (las ya caducadas no se incluyen).

    La contraseña caduca en password_next_rotation (N/A si la cuenta no la hace caducar). Las access keys no caducan
    en AWS: se les aplica el límite de antigüedad `max_age_days` desde su última rotación.
    """
    max_age = params.get("max_age_days", DEFAULT_MAX_AGE_DAYS)
    warning = params.get("warning_days", DEFAULT_WARNING_DAYS)
    today = _now().date()

    found = []
    for row in _load_credential_report(session, params):
        expirations = []  # (credencial, fecha de caducidad)
        if row["password_enabled"] == "true":  # la root (not_supported) no tiene fecha de caducidad
            expirations.append(("password", _parse_date(row["password_next_rotation"])))
        for n in (1, 2):
            rotated = _parse_date(row[f"access_key_{n}_last_rotated"])
            if row[f"access_key_{n}_active"] == "true" and rotated:
                expirations.append((f"access_key_{n}", rotated + timedelta(days=max_age)))

        for credential, expires in expirations:
            if expires is None:
                continue
            expires_on = expires.astimezone(timezone.utc).date()
            days_left = (expires_on - today).days  # días de calendario UTC
            if 0 <= days_left < warning:
                found.append({"UserName": row["user"], "Credential": credential,
                              "ExpiresOn": expires_on.isoformat(), "DaysLeft": days_left})
    return found


def iam_user_without_mfa(session, params):
    """Usuarios con contraseña de consola (root incluido) y sin MFA activo, según el informe de credenciales.

    En la fila de la cuenta root el informe da password_enabled = "not_supported": la root siempre tiene contraseña.
    """
    found = []
    for row in _load_credential_report(session, params):
        has_console = row["password_enabled"] in ("true", "not_supported")
        if not has_console or row["mfa_active"] == "true":
            continue
        last_used = row["password_last_used"]
        found.append({
            "UserName": row["user"],
            "PasswordLastUsed": last_used if last_used not in ("N/A", "no_information", "") else None,
            "ActiveAccessKeys": sum(row[f"access_key_{n}_active"] == "true" for n in (1, 2)),
        })
    return found


# --- EC2 ---

OPEN_SOURCES = (("IpRanges", "CidrIp", "0.0.0.0/0"), ("Ipv6Ranges", "CidrIpv6", "::/0"))


def _enabled_regions(session):
    """Regiones habilitadas de la cuenta, ordenadas (describe_regions no devuelve las opt-in desactivadas)."""
    regions = session.create_client("ec2", region_name=DEFAULT_REGION).describe_regions()["Regions"]
    return sorted(item["RegionName"] for item in regions)


def _exposed_ports(group, critical_ports):
    """Puertos críticos abiertos a Internet en un Security Group y orígenes abiertos que los exponen."""
    exposed, sources = {}, []
    for permission in group.get("IpPermissions", []):
        if permission.get("IpProtocol") not in ("tcp", "-1"):
            continue
        open_sources = [cidr for key, field, cidr in OPEN_SOURCES
                        if any(item.get(field) == cidr for item in permission.get(key, []))]
        if not open_sources:  # origen privado, otro Security Group o prefix list
            continue
        # Con protocolo -1 AWS no devuelve puertos: todo el tráfico está permitido.
        all_traffic = permission["IpProtocol"] == "-1"
        low = 0 if all_traffic else permission.get("FromPort", 0)
        high = 65535 if all_traffic else permission.get("ToPort", 65535)
        matched = {entry["port"]: entry["name"] for entry in critical_ports if low <= entry["port"] <= high}
        if matched:
            exposed.update(matched)
            sources += [source for source in open_sources if source not in sources]
    return exposed, sources


def ec2_sg_critical_exposed_ports(session, params):
    """Security Groups de todas las regiones habilitadas con puertos críticos abiertos a 0.0.0.0/0 o ::/0."""
    critical_ports = params.get("ports")
    if not critical_ports:
        raise ValueError("faltan los puertos críticos: define params.ports en la regla")

    found = []
    for region in _enabled_regions(session):
        client = session.create_client("ec2", region_name=region)
        try:
            response = client.get_paginator("describe_security_groups").paginate().build_full_result()
        except ClientError as e:
            raise ValueError(f"región {region}: {e}") from e
        for group in response.get("SecurityGroups", []):
            exposed, sources = _exposed_ports(group, critical_ports)
            if exposed:
                found.append({
                    "GroupId": group["GroupId"],
                    "Name": group.get("GroupName"),
                    "Region": region,
                    "VPC": group.get("VpcId"),
                    "Ports": ", ".join(f"{port} ({name})" for port, name in sorted(exposed.items())),
                    "Source": ", ".join(sources),
                })
    return found


def ec2_eip_unassigned(session, params):
    """Elastic IPs de todas las regiones habilitadas sin asociar a ningún recurso."""
    found = []
    for region in _enabled_regions(session):
        client = session.create_client("ec2", region_name=region)
        try:
            addresses = client.describe_addresses().get("Addresses", [])
        except ClientError as e:
            raise ValueError(f"región {region}: {e}") from e
        for address in addresses:
            if address.get("AssociationId"):
                continue
            if address.get("PublicIpv4Pool", "amazon") != "amazon":  # BYOIP: AWS no la cobra
                continue
            tags = {tag["Key"]: tag["Value"] for tag in address.get("Tags", [])}
            found.append({
                "AllocationId": address.get("AllocationId"),
                "PublicIp": address.get("PublicIp"),
                "Region": region,
                "Name": tags.get("Name"),
            })
    return found


def ec2_public_ip_without_lb(session, params):
    """ENIs con IPv4 pública que no son de un balanceador, NAT Gateway ni otro tipo excluido en los params."""
    excluded_types = set(params.get("excluded_interface_types", []))
    excluded_requesters = set(params.get("excluded_requester_ids", []))

    found = []
    for region in _enabled_regions(session):
        client = session.create_client("ec2", region_name=region)
        try:
            response = client.get_paginator("describe_network_interfaces").paginate().build_full_result()
        except ClientError as e:
            raise ValueError(f"región {region}: {e}") from e
        for eni in response.get("NetworkInterfaces", []):
            association = eni.get("Association") or {}
            if not association.get("PublicIp"):
                continue
            if eni.get("InterfaceType") in excluded_types or eni.get("RequesterId") in excluded_requesters:
                continue
            instance_id = (eni.get("Attachment") or {}).get("InstanceId")
            found.append({
                "PublicIp": association["PublicIp"],
                "Region": region,
                "ResourceId": instance_id or eni["NetworkInterfaceId"],
                "ResourceType": "instance" if instance_id else eni.get("InterfaceType"),
                "IpType": "elastic" if association.get("AllocationId") else "efímera",
            })
    return found


CHECKS = {
    "s3_bucket_exposed_content": s3_bucket_exposed_content,
    "s3_bucket_public_acl": s3_bucket_public_acl,
    "iam_user_excess_admin_roles": iam_user_excess_admin_roles,
    "iam_user_without_mfa": iam_user_without_mfa,
    "iam_credentials_older_than": iam_credentials_older_than,
    "iam_credentials_expiring_soon": iam_credentials_expiring_soon,
    "ec2_sg_critical_exposed_ports": ec2_sg_critical_exposed_ports,
    "ec2_eip_unassigned": ec2_eip_unassigned,
    "ec2_public_ip_without_lb": ec2_public_ip_without_lb,
}
