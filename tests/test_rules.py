import json
from datetime import datetime, timezone
from urllib.parse import quote

import botocore.session
import pytest
import yaml
from botocore.stub import Stubber

from engine import RULES_DIR, filter_rules, load_rules, run_check, run_rule

SESSION = botocore.session.get_session()
RULES = load_rules()
EXAMPLE_RULE = next(rule for rule in RULES if rule["id"] == "ec2-sg-open-ssh")


@pytest.mark.parametrize("rule", [r for r in RULES if "operation" in r], ids=lambda rule: rule["id"])
def test_rule_operation_exists_in_botocore(rule):
    client = SESSION.create_client(rule["service"], region_name="us-east-1")
    assert hasattr(client, rule["operation"]), f"{rule['id']}: {rule['service']} no tiene {rule['operation']}"


def test_rules_folder_is_not_empty():
    assert RULES, f"No hay reglas en {RULES_DIR}"


def test_load_rules_reports_file_and_missing_field(tmp_path):
    (tmp_path / "broken.yaml").write_text("id: broken\nrisk: high\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"broken\.yaml: faltan los campos"):
        load_rules(tmp_path)


def test_load_rules_rejects_invalid_risk(tmp_path):
    rule = dict(EXAMPLE_RULE, risk="extreme")
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    with pytest.raises(ValueError, match="risk 'extreme' no válido"):
        load_rules(tmp_path)


def test_load_rules_rejects_invalid_jmespath(tmp_path):
    rule = dict(EXAMPLE_RULE, query="SecurityGroups[?")
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    with pytest.raises(ValueError, match="expresión JMESPath no válida"):
        load_rules(tmp_path)


def test_load_rules_rejects_duplicated_ids(tmp_path):
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(EXAMPLE_RULE), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(EXAMPLE_RULE), encoding="utf-8")
    with pytest.raises(ValueError, match="IDs de regla duplicados"):
        load_rules(tmp_path)


def _rule(rule_id, risk):
    return {"id": rule_id, "risk": risk}


FILTER_RULES = [_rule("a", "low"), _rule("b", "mid"), _rule("c", "high"), _rule("d", "critical")]


def test_filter_by_minimum_risk_includes_higher_levels():
    selected = filter_rules(FILTER_RULES, risk="high")
    assert [rule["id"] for rule in selected] == ["c", "d"]


def test_filter_by_rule_id():
    selected = filter_rules(FILTER_RULES, rule_ids=("b", "d"))
    assert [rule["id"] for rule in selected] == ["b", "d"]


def test_filter_by_unknown_rule_id_fails():
    with pytest.raises(ValueError, match="desconocida"):
        filter_rules(FILTER_RULES, rule_ids=("nope",))


def test_ec2_sg_open_ssh_finds_only_open_ssh_groups():
    client = SESSION.create_client("ec2", region_name="us-east-1")
    response = {
        "SecurityGroups": [
            {  # SSH desde Internet (IPv4) -> hallazgo
                "GroupId": "sg-open", "GroupName": "web", "VpcId": "vpc-1",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}],
            },
            {  # Todo el tráfico desde Internet -> hallazgo
                "GroupId": "sg-all", "GroupName": "all", "VpcId": "vpc-1",
                "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}],
            },
            {  # SSH desde Internet (IPv6) -> hallazgo
                "GroupId": "sg-ipv6", "GroupName": "v6", "VpcId": "vpc-2",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                   "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
            },
            {  # SSH solo desde una red privada -> sin hallazgo
                "GroupId": "sg-private", "GroupName": "internal", "VpcId": "vpc-1",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                   "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}],
            },
            {  # HTTPS desde Internet -> sin hallazgo
                "GroupId": "sg-https", "GroupName": "public", "VpcId": "vpc-1",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}],
            },
        ]
    }

    with Stubber(client) as stubber:
        stubber.add_response("describe_security_groups", response, {})
        rows = run_rule(client, EXAMPLE_RULE)
        stubber.assert_no_pending_responses()

    assert [row["GroupId"] for row in rows] == ["sg-open", "sg-all", "sg-ipv6"]
    assert rows[0] == {"GroupId": "sg-open", "Name": "web", "VPC": "vpc-1"}


def test_run_rule_fails_for_unknown_operation():
    client = SESSION.create_client("ec2", region_name="us-east-1")
    with pytest.raises(ValueError, match="no tiene la operación 'describe_nothing'"):
        run_rule(client, dict(EXAMPLE_RULE, operation="describe_nothing"))


def test_load_rules_rejects_unknown_check(tmp_path):
    rule = {key: EXAMPLE_RULE[key] for key in ("id", "name", "description", "risk", "service", "columns")}
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump(dict(rule, check="nope")), encoding="utf-8")
    with pytest.raises(ValueError, match="check 'nope' desconocido"):
        load_rules(tmp_path)


# --- Reglas S3 (checks.py) ---

PUBLIC_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
OWNER = {"ID": "owner"}
NO_POLICY = ("NoSuchBucketPolicy", "The bucket policy does not exist")
NO_BLOCK = ("NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found")


def _acl(*grants):
    """ACL con el propietario y, opcionalmente, concesiones (uri, permiso) a grupos públicos."""
    return {"Owner": OWNER, "Grants": [
        {"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission} for uri, permission in grants
    ]}


class FakeSession:
    """Sesión que reparte clientes con Stubber: uno para ListBuckets (us-east-1) y uno por región."""

    def __init__(self, buckets, regional_responses):
        self.stubbers, self.clients = [], {}
        self.clients["us-east-1"] = self._client("us-east-1", [
            ("list_buckets", {"Buckets": [{"Name": n, "BucketRegion": r} for n, r in buckets], "Owner": OWNER}, {}),
        ])
        for region, responses in regional_responses.items():
            self.clients[region] = self._client(region, responses)
        self.created = []

    def _client(self, region, responses):
        client = SESSION.create_client("s3", region_name=region, aws_access_key_id="a", aws_secret_access_key="b")
        stubber = Stubber(client)
        for operation, response, params in responses:
            if isinstance(response, tuple):
                stubber.add_client_error(operation, service_error_code=response[0], service_message=response[1],
                                         expected_params=params)
            else:
                stubber.add_response(operation, response, params)
        stubber.activate()
        self.stubbers.append(stubber)
        return client

    def create_client(self, service, region_name):
        assert service == "s3"
        self.created.append(region_name)
        return self.clients[region_name]

    def assert_all_calls_made(self):
        for stubber in self.stubbers:
            stubber.assert_no_pending_responses()


def _bucket_responses(name, acl, policy_public=None, block=None):
    """Respuestas de una inspección de bucket, en el orden en que las pide el check."""
    params = {"Bucket": name}
    policy = NO_POLICY if policy_public is None else {"PolicyStatus": {"IsPublic": policy_public}}
    block_response = NO_BLOCK if block is None else {"PublicAccessBlockConfiguration": block}
    return [
        ("get_public_access_block", block_response, params),
        ("get_bucket_policy_status", policy, params),
        ("get_bucket_acl", acl, params),
    ]


def _s3_session():
    buckets = [("private", "eu-west-1"), ("policy-public", "eu-west-1"), ("acl-read", "us-west-2"),
               ("acl-write", "us-west-2"), ("policy-blocked", "us-west-2"), ("acl-ignored", "us-west-2")]
    return FakeSession(buckets, {
        "eu-west-1": (
            _bucket_responses("policy-public", _acl(), policy_public=True)
            + _bucket_responses("private", _acl(), policy_public=False)
        ),
        "us-west-2": (
            _bucket_responses("acl-ignored", _acl((PUBLIC_URI, "READ")), block={"IgnorePublicAcls": True})
            + _bucket_responses("acl-read", _acl((AUTH_URI, "READ")))
            + _bucket_responses("acl-write", _acl((PUBLIC_URI, "WRITE")))
            + _bucket_responses("policy-blocked", _acl(), policy_public=True, block={"RestrictPublicBuckets": True})
        ),
    })


S3_EXPOSED = next(rule for rule in RULES if rule["id"] == "s3-bucket-exposed-content")
S3_ACL = next(rule for rule in RULES if rule["id"] == "s3-bucket-public-acl")


def test_s3_rules_have_expected_risk():
    assert S3_EXPOSED["risk"] == "critical"
    assert S3_ACL["risk"] == "mid"


def test_s3_exposed_content_across_regions():
    session = _s3_session()
    rows = run_check(session, S3_EXPOSED)
    session.assert_all_calls_made()
    assert rows == [
        {"BucketId": "policy-public", "Region": "eu-west-1"},
        {"BucketId": "acl-read", "Region": "us-west-2"},
    ]


def test_s3_public_acl_reports_any_public_grant_even_if_blocked():
    session = _s3_session()
    rows = run_check(session, S3_ACL)
    session.assert_all_calls_made()
    assert rows == [
        {"BucketId": "acl-ignored", "Region": "us-west-2", "Permissions": "READ"},
        {"BucketId": "acl-read", "Region": "us-west-2", "Permissions": "READ"},
        {"BucketId": "acl-write", "Region": "us-west-2", "Permissions": "WRITE"},
    ]


def test_s3_check_without_buckets_returns_no_rows():
    session = FakeSession([], {})
    assert run_check(session, S3_EXPOSED) == []


def test_s3_check_names_the_bucket_when_access_is_denied():
    session = FakeSession([("locked", "eu-west-1")], {
        "eu-west-1": [("get_public_access_block", ("AccessDenied", "Access Denied"), {"Bucket": "locked"})],
    })
    with pytest.raises(ValueError, match=r"bucket locked \(eu-west-1\)"):
        run_check(session, S3_EXPOSED)


# --- Regla IAM (checks.py) ---

IAM_EXCESS = next(rule for rule in RULES if rule["id"] == "iam-user-excess-admin-roles")
AWS = "arn:aws:iam::aws:policy/"
ACCOUNT = "arn:aws:iam::123456789012"
ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READ_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}


def _enc(document):
    """Los documentos llegan de IAM como JSON URL-encoded; Stubber no pasa por el decodificador de botocore."""
    return quote(json.dumps(document))


def _attached(*names):
    return [{"PolicyName": name, "PolicyArn": AWS + name} for name in names]


def _user(name, managed=(), inline=(), groups=()):
    return {"Path": "/", "UserName": name, "UserId": name.ljust(16, "X"), "Arn": f"{ACCOUNT}:user/{name}",
            "CreateDate": "2024-01-01", "GroupList": list(groups), "AttachedManagedPolicies": _attached(*managed),
            "UserPolicyList": [{"PolicyName": n, "PolicyDocument": _enc(d)} for n, d in inline]}


def _group(name, managed=(), inline=()):
    return {"Path": "/", "GroupName": name, "GroupId": name.ljust(16, "X"), "Arn": f"{ACCOUNT}:group/{name}",
            "CreateDate": "2024-01-01", "AttachedManagedPolicies": _attached(*managed),
            "GroupPolicyList": [{"PolicyName": n, "PolicyDocument": _enc(d)} for n, d in inline]}


def _role(name, trusted_users=(), managed=()):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": [f"{ACCOUNT}:user/{u}" for u in trusted_users]},
         "Action": "sts:AssumeRole"}]}
    return {"Path": "/", "RoleName": name, "RoleId": name.ljust(16, "X"), "Arn": f"{ACCOUNT}:role/{name}",
            "CreateDate": "2024-01-01", "AssumeRolePolicyDocument": _enc(trust), "AttachedManagedPolicies": _attached(*managed)}


def _iam_session(users, groups=(), roles=(), policies=()):
    client = SESSION.create_client("iam", region_name="us-east-1", aws_access_key_id="a", aws_secret_access_key="b")
    stubber = Stubber(client)
    stubber.add_response("get_account_authorization_details", {
        "UserDetailList": users, "GroupDetailList": list(groups), "RoleDetailList": list(roles),
        "Policies": list(policies), "IsTruncated": False}, {})
    stubber.activate()
    session = FakeSession([], {})
    session.create_client = lambda service, region_name: client
    return session


def test_iam_rule_has_expected_risk():
    assert IAM_EXCESS["risk"] == "mid"
    assert IAM_EXCESS["params"]["threshold"] == 3


def test_iam_exactly_threshold_admin_assignments_is_not_reported():
    session = _iam_session([_user("bob", managed=["AdministratorAccess", "IAMFullAccess", "PowerUserAccess"])])
    assert run_check(session, IAM_EXCESS) == []


def test_iam_counts_direct_group_role_and_inline_assignments():
    custom = {"PolicyName": "custom-full", "Arn": f"{ACCOUNT}:policy/custom-full", "DefaultVersionId": "v1",
              "PolicyVersionList": [{"Document": _enc(ADMIN_DOC), "VersionId": "v1", "IsDefaultVersion": True}]}
    alice = _user("alice", managed=["AdministratorAccess", "ViewOnlyAccess"], groups=["devops", "ops"],
                  inline=[("inline-admin", ADMIN_DOC), ("inline-read", READ_DOC)])
    alice["AttachedManagedPolicies"].append({"PolicyName": "custom-full", "PolicyArn": custom["Arn"]})
    session = _iam_session(
        [alice, _user("carol", managed=["AdministratorAccess"])],
        groups=[_group("devops", managed=["IAMFullAccess"]), _group("ops", managed=["PowerUserAccess"])],
        roles=[_role("ops-admin", trusted_users=["alice"], managed=["AdministratorAccess"]),
               _role("not-admin", trusted_users=["alice"], managed=["ViewOnlyAccess"]),
               _role("other-user", trusted_users=["carol"], managed=["AdministratorAccess"])],
        policies=[custom],
    )
    rows = run_check(session, IAM_EXCESS)
    assert rows == [{
        "UserName": "alice", "AdminCount": 6,
        "AdminRoles": "AdministratorAccess (directa), custom-full (directa), inline-admin (inline), "
                      "IAMFullAccess (grupo devops), PowerUserAccess (grupo ops), ops-admin (rol)",
    }]


def test_iam_same_policy_via_two_paths_counts_once():
    user = _user("dave", managed=["AdministratorAccess", "IAMFullAccess", "PowerUserAccess"], groups=["admins"])
    session = _iam_session([user], groups=[_group("admins", managed=["AdministratorAccess"])])
    assert run_check(session, IAM_EXCESS) == []  # 3 asignaciones distintas, no 4


def test_iam_custom_policy_with_wildcard_action_counts_as_admin():
    user = _user("erin", managed=["AdministratorAccess", "IAMFullAccess", "PowerUserAccess"],
                 inline=[("star", ADMIN_DOC)])
    rows = run_check(_iam_session([user]), IAM_EXCESS)
    assert [(row["UserName"], row["AdminCount"]) for row in rows] == [("erin", 4)]


def test_iam_threshold_and_admin_policies_come_from_rule_params():
    rule = dict(IAM_EXCESS, params={"threshold": 1, "admin_policies": ["ViewOnlyAccess"]})
    user = _user("frank", managed=["ViewOnlyAccess", "AdministratorAccess"])
    assert run_check(_iam_session([user]), rule) == []  # solo 1 asignación cuenta


# --- Regla EC2 puertos críticos (checks.py) ---

PORTS_RULE = next(rule for rule in RULES if rule["id"] == "ec2-sg-critical-exposed-ports")
ANYWHERE_V4 = {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
ANYWHERE_V6 = {"IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
PRIVATE = {"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}
FROM_SG = {"IpRanges": [], "Ipv6Ranges": [], "UserIdGroupPairs": [{"GroupId": "sg-other", "UserId": "123456789012"}]}


def _tcp(low, high, source, protocol="tcp"):
    return dict({"IpProtocol": protocol, "FromPort": low, "ToPort": high}, **source)


def _sg(group_id, name, vpc, *permissions):
    return {"GroupId": group_id, "GroupName": name, "VpcId": vpc, "IpPermissions": list(permissions)}


class FakeEc2Session:
    """Sesión que reparte un cliente EC2 con Stubber por región. us-east-1 responde además a describe_regions."""

    def __init__(self, groups_by_region, operation="describe_security_groups", key="SecurityGroups"):
        self.clients, self.stubbers = {}, []
        for region, groups in groups_by_region.items():
            client = SESSION.create_client("ec2", region_name=region, aws_access_key_id="a", aws_secret_access_key="b")
            stubber = Stubber(client)
            if region == "us-east-1":
                stubber.add_response("describe_regions",
                                     {"Regions": [{"RegionName": name} for name in groups_by_region]}, {})
            stubber.add_response(operation, {key: groups}, {})
            stubber.activate()
            self.clients[region] = client
            self.stubbers.append(stubber)

    def create_client(self, service, region_name):
        assert service == "ec2"
        return self.clients[region_name]

    def assert_all_calls_made(self):
        for stubber in self.stubbers:
            stubber.assert_no_pending_responses()


def test_ports_rule_has_expected_risk_and_ports():
    assert PORTS_RULE["risk"] == "critical"
    names = {entry["port"]: entry["name"] for entry in PORTS_RULE["params"]["ports"]}
    assert names[22] == "SSH" and names[3389] == "RDP" and names[27018] == "MongoDB" and names[2380] == "etcd"


def test_ports_open_to_internet_are_reported_with_all_their_ports():
    session = FakeEc2Session({
        "eu-west-1": [
            _sg("sg-web", "web", "vpc-1", _tcp(22, 22, ANYWHERE_V4), _tcp(3306, 3306, ANYWHERE_V4)),
            _sg("sg-range", "range", "vpc-1", _tcp(0, 65535, ANYWHERE_V4)),
            _sg("sg-all", "all", "vpc-2", {"IpProtocol": "-1", **ANYWHERE_V6}),
        ],
        "us-east-1": [
            _sg("sg-rdp", "default", "vpc-3", _tcp(3389, 3389, ANYWHERE_V4), _tcp(3389, 3389, ANYWHERE_V6)),
            _sg("sg-v6", "v6", "vpc-3", _tcp(5432, 5432, ANYWHERE_V6)),
        ],
    })
    rows = run_check(session, PORTS_RULE)
    session.assert_all_calls_made()

    assert [(row["GroupId"], row["Region"]) for row in rows] == [
        ("sg-web", "eu-west-1"), ("sg-range", "eu-west-1"), ("sg-all", "eu-west-1"),
        ("sg-rdp", "us-east-1"), ("sg-v6", "us-east-1"),
    ]
    assert rows[0] == {"GroupId": "sg-web", "Name": "web", "Region": "eu-west-1", "VPC": "vpc-1",
                       "Ports": "22 (SSH), 3306 (MySQL)", "Source": "0.0.0.0/0"}
    assert rows[1]["Ports"].count("(") == len(PORTS_RULE["params"]["ports"])  # el rango expone toda la lista
    assert rows[2]["Ports"].startswith("21 (FTP), 22 (SSH)") and rows[2]["Source"] == "::/0"
    assert rows[3]["Ports"] == "3389 (RDP)" and rows[3]["Source"] == "0.0.0.0/0, ::/0"
    assert rows[4]["Source"] == "::/0"


def test_ports_not_exposed_to_internet_are_ignored():
    session = FakeEc2Session({"us-east-1": [
        _sg("sg-private", "private", "vpc-1", _tcp(22, 22, PRIVATE), _tcp(3306, 3306, PRIVATE)),
        _sg("sg-from-sg", "from-sg", "vpc-1", _tcp(5432, 5432, FROM_SG)),
        _sg("sg-https", "https", "vpc-1", _tcp(443, 443, ANYWHERE_V4), _tcp(80, 80, ANYWHERE_V6)),
        _sg("sg-udp", "udp", "vpc-1", _tcp(0, 65535, ANYWHERE_V4, protocol="udp")),
        _sg("sg-empty", "empty", "vpc-1"),
    ]})
    assert run_check(session, PORTS_RULE) == []


def test_ports_come_from_rule_params():
    rule = dict(PORTS_RULE, params={"ports": [{"port": 8080, "name": "Admin"}]})
    session = FakeEc2Session({"us-east-1": [
        _sg("sg-admin", "admin", "vpc-1", _tcp(8080, 8080, ANYWHERE_V4)),
        _sg("sg-ssh", "ssh", "vpc-1", _tcp(22, 22, ANYWHERE_V4)),  # SSH ya no es crítico con esta lista
    ]})
    rows = run_check(session, rule)
    assert [(row["GroupId"], row["Ports"]) for row in rows] == [("sg-admin", "8080 (Admin)")]


def test_ports_check_requires_ports_param():
    with pytest.raises(ValueError, match="params.ports"):
        run_check(FakeEc2Session({"us-east-1": []}), dict(PORTS_RULE, params={}))


# --- Regla EC2 Elastic IPs sin asignar (checks.py) ---

EIP_RULE = next(rule for rule in RULES if rule["id"] == "ec2-eip-unassigned")


def _eip(allocation_id, public_ip, association_id=None, pool="amazon", name=None):
    address = {"AllocationId": allocation_id, "PublicIp": public_ip, "PublicIpv4Pool": pool, "Domain": "vpc"}
    if association_id:
        address["AssociationId"] = association_id
        address["InstanceId"] = "i-0123456789abcdef0"
    if name:
        address["Tags"] = [{"Key": "env", "Value": "dev"}, {"Key": "Name", "Value": name}]
    return address


def _eip_session(addresses_by_region):
    return FakeEc2Session(addresses_by_region, operation="describe_addresses", key="Addresses")


def test_eip_rule_has_expected_risk_and_columns():
    assert EIP_RULE["risk"] == "low"
    assert list(EIP_RULE["columns"]) == ["AllocationId", "PublicIp", "Region", "Name"]


def test_eip_unassigned_across_regions_with_name():
    session = _eip_session({
        "eu-west-1": [_eip("eipalloc-0a", "54.12.34.56", name="old-web")],
        "us-east-1": [_eip("eipalloc-0f", "3.210.98.76")],  # sin etiqueta Name
    })
    rows = run_check(session, EIP_RULE)
    session.assert_all_calls_made()
    assert rows == [
        {"AllocationId": "eipalloc-0a", "PublicIp": "54.12.34.56", "Region": "eu-west-1",
         "Name": "old-web"},
        {"AllocationId": "eipalloc-0f", "PublicIp": "3.210.98.76", "Region": "us-east-1",
         "Name": None},
    ]


def test_eip_associated_or_byoip_are_ignored():
    session = _eip_session({"us-east-1": [
        _eip("eipalloc-inst", "1.1.1.1", association_id="eipassoc-1"),
        _eip("eipalloc-byoip", "2.2.2.2", pool="ipv4pool-ec2-0123456789abcdef0"),
    ]})
    assert run_check(session, EIP_RULE) == []


# --- Regla EC2 IPs públicas sin balanceador (checks.py) ---

LB_RULE = next(rule for rule in RULES if rule["id"] == "ec2-public-ip-without-lb")


def _eni(eni_id, public_ip=None, allocation_id=None, instance_id=None, interface_type="interface", requester=None):
    eni = {"NetworkInterfaceId": eni_id, "InterfaceType": interface_type}
    if public_ip:
        eni["Association"] = {"PublicIp": public_ip}
        if allocation_id:
            eni["Association"]["AllocationId"] = allocation_id
    if instance_id:
        eni["Attachment"] = {"InstanceId": instance_id}
    if requester:
        eni["RequesterId"] = requester
    return eni


def _lb_session(enis_by_region):
    return FakeEc2Session(enis_by_region, operation="describe_network_interfaces", key="NetworkInterfaces")


def test_lb_rule_has_expected_risk_and_exclusions():
    assert LB_RULE["risk"] == "mid"
    assert set(LB_RULE["params"]["excluded_interface_types"]) == {
        "network_load_balancer", "gateway_load_balancer", "nat_gateway"}
    assert LB_RULE["params"]["excluded_requester_ids"] == ["amazon-elb"]


def test_public_ips_without_lb_across_regions():
    session = _lb_session({
        "eu-west-1": [_eni("eni-1", "54.12.34.56", instance_id="i-0a1b2c3d4e5f67890")],  # instancia, IP efímera
        "us-east-1": [_eni("eni-0f9e8d7c6b5a43210", "3.210.98.76", allocation_id="eipalloc-1")],  # ENI suelta, EIP
    })
    rows = run_check(session, LB_RULE)
    session.assert_all_calls_made()
    assert rows == [
        {"PublicIp": "54.12.34.56", "Region": "eu-west-1", "ResourceId": "i-0a1b2c3d4e5f67890",
         "ResourceType": "instance", "IpType": "efímera"},
        {"PublicIp": "3.210.98.76", "Region": "us-east-1", "ResourceId": "eni-0f9e8d7c6b5a43210",
         "ResourceType": "interface", "IpType": "elastic"},
    ]


def test_public_ips_of_load_balancers_nat_and_private_enis_are_ignored():
    session = _lb_session({"us-east-1": [
        _eni("eni-alb", "1.1.1.1", requester="amazon-elb"),
        _eni("eni-nlb", "2.2.2.2", interface_type="network_load_balancer"),
        _eni("eni-gwlb", "3.3.3.3", interface_type="gateway_load_balancer"),
        _eni("eni-nat", "4.4.4.4", allocation_id="eipalloc-2", interface_type="nat_gateway"),
        _eni("eni-private", instance_id="i-0123456789abcdef0"),  # sin IP pública
    ]})
    assert run_check(session, LB_RULE) == []


def test_exclusions_come_from_rule_params():
    rule = dict(LB_RULE, params={"excluded_interface_types": ["lambda"], "excluded_requester_ids": []})
    session = _lb_session({"us-east-1": [
        _eni("eni-lambda", "1.1.1.1", interface_type="lambda"),
        _eni("eni-alb", "2.2.2.2", requester="amazon-elb"),  # ya no se excluye con esta lista
    ]})
    rows = run_check(session, rule)
    assert [row["ResourceId"] for row in rows] == ["eni-alb"]


# --- Regla IAM usuarios sin MFA (checks.py) ---

MFA_RULE = next(rule for rule in RULES if rule["id"] == "iam-user-without-mfa")
REPORT_HEADER = ("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
                 "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
                 "access_key_2_active,access_key_2_last_rotated")


def _report_row(user, password="true", last_used="N/A", mfa="false", keys=(), ):
    key1, key2 = ("true" if n < len(keys) else "false" for n in (0, 1))
    return (f"{user},arn:aws:iam::123456789012:user/{user},2024-01-01T00:00:00+00:00,{password},{last_used},"
            f"N/A,N/A,{mfa},{key1},N/A,{key2},N/A")


def _report(*rows):
    return ("\n".join([REPORT_HEADER, *rows]) + "\n").encode("utf-8")


def _mfa_session(*responses):
    """Sesión IAM con las respuestas de generate_credential_report y get_credential_report en orden."""
    client = SESSION.create_client("iam", region_name="us-east-1", aws_access_key_id="a", aws_secret_access_key="b")
    stubber = Stubber(client)
    for operation, response in responses:
        stubber.add_response(operation, response, {})
    stubber.activate()
    session = FakeSession([], {})
    session.create_client = lambda service, region_name: client
    session.stubber = stubber
    return session


def _generate(state):
    return ("generate_credential_report", {"State": state})


def _download(content):
    return ("get_credential_report", {"Content": content, "ReportFormat": "text/csv"})


@pytest.fixture
def no_sleep(monkeypatch):
    waits = []
    monkeypatch.setattr("checks.time.sleep", waits.append)
    return waits


def test_mfa_rule_has_expected_risk():
    assert MFA_RULE["risk"] == "high"


def test_users_with_password_and_no_mfa_are_reported(no_sleep):
    report = _report(
        _report_row("<root_account>", password="not_supported", last_used="2026-10-02T08:15:00+00:00"),
        _report_row("alice", last_used="2026-11-18T17:42:10+00:00", keys=(1,)),
        _report_row("bob", last_used="no_information"),  # nunca ha iniciado sesión
        _report_row("carol", mfa="true", last_used="2026-11-01T00:00:00+00:00"),  # con MFA
        _report_row("deploy", password="false", keys=(1, 2)),  # solo access keys
    )
    session = _mfa_session(_generate("COMPLETE"), _download(report))
    rows = run_check(session, MFA_RULE)
    session.stubber.assert_no_pending_responses()
    assert rows == [
        {"UserName": "<root_account>", "PasswordLastUsed": "2026-10-02T08:15:00+00:00", "ActiveAccessKeys": 0},
        {"UserName": "alice", "PasswordLastUsed": "2026-11-18T17:42:10+00:00", "ActiveAccessKeys": 1},
        {"UserName": "bob", "PasswordLastUsed": None, "ActiveAccessKeys": 0},
    ]


def test_root_with_mfa_is_not_reported(no_sleep):
    report = _report(_report_row("<root_account>", password="not_supported", mfa="true"))
    assert run_check(_mfa_session(_generate("COMPLETE"), _download(report)), MFA_RULE) == []


def test_credential_report_is_awaited_until_complete(no_sleep):
    report = _report(_report_row("alice"))
    session = _mfa_session(_generate("STARTED"), _generate("INPROGRESS"), _generate("COMPLETE"), _download(report))
    rows = run_check(session, MFA_RULE)
    session.stubber.assert_no_pending_responses()
    assert [row["UserName"] for row in rows] == ["alice"]
    assert no_sleep == [2, 2]  # dos esperas de report_poll_interval_seconds


def test_credential_report_that_never_completes_fails(no_sleep):
    rule = dict(MFA_RULE, params={"report_timeout_seconds": 4, "report_poll_interval_seconds": 2})
    session = _mfa_session(*[_generate("INPROGRESS")] * 3)  # 1 + 2 reintentos (4 s / 2 s)
    with pytest.raises(ValueError, match="no generó el informe de credenciales en 4 s"):
        run_check(session, rule)
    assert no_sleep == [2, 2]


# --- Regla IAM credenciales antiguas (checks.py) ---

AGE_RULE = next(rule for rule in RULES if rule["id"] == "iam-credentials-older-than-one-year")
TODAY = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
CREATED = "2020-01-01T00:00:00+00:00"


def _age_row(user, password="true", changed="N/A", created=CREATED, key1=None, key2=None, next_rotation="N/A"):
    """Fila del informe. key1/key2: None (sin key), o (activa, fecha de rotación)."""
    def key(item):
        active, rotated = item if item else ("false", "N/A")
        return f"{active},{rotated}"
    return (f"{user},arn:aws:iam::123456789012:user/{user},{created},{password},N/A,{changed},{next_rotation},false,"
            f"{key(key1)},{key(key2)}")


@pytest.fixture
def fixed_today(monkeypatch):
    monkeypatch.setattr("checks._now", lambda: TODAY)


def _age_rows(*rows, rule=AGE_RULE):
    session = _mfa_session(_generate("COMPLETE"), _download(_report(*rows)))
    return run_check(session, rule)


def test_age_rule_has_expected_risk_and_threshold():
    assert AGE_RULE["risk"] == "mid"
    assert AGE_RULE["params"]["max_age_days"] == 365


def test_old_password_is_reported_and_recent_one_is_not(fixed_today):
    rows = _age_rows(
        _age_row("alice", changed="2025-06-01T12:30:00+00:00"),
        _age_row("bob", changed="2026-06-01T12:30:00+00:00"),
    )
    assert rows == [{"UserName": "alice", "Credential": "password",
                     "LastRotated": "2025-06-01T12:30:00+00:00", "AgeDays": 538}]


def test_password_never_changed_uses_user_creation_date(fixed_today):
    rows = _age_rows(
        _age_row("old-user", changed="N/A", created="2024-01-01T00:00:00+00:00"),
        _age_row("new-user", changed="N/A", created="2026-10-01T00:00:00+00:00"),
    )
    assert [(row["UserName"], row["LastRotated"]) for row in rows] == [("old-user", "2024-01-01T00:00:00+00:00")]


def test_only_active_old_access_keys_are_reported(fixed_today):
    rows = _age_rows(
        _age_row("deploy", password="false", key1=("true", "2025-09-20T16:45:00+00:00")),
        _age_row("ci", password="false", key1=("false", "2020-01-01T00:00:00+00:00"),
                 key2=("true", "2024-02-14T08:00:00+00:00")),
        _age_row("fresh", password="false", key1=("true", "2026-10-01T00:00:00+00:00")),
    )
    assert [(row["UserName"], row["Credential"], row["AgeDays"]) for row in rows] == [
        ("deploy", "access_key_1", 427), ("ci", "access_key_2", 1011)]


def test_user_without_password_and_recent_keys_is_not_reported(fixed_today):
    assert _age_rows(_age_row("svc", password="false", key1=("true", "2026-09-01T00:00:00+00:00"))) == []


def test_user_with_old_password_and_two_old_keys_gives_three_rows(fixed_today):
    rows = _age_rows(_age_row("alice", changed="2025-06-01T12:30:00+00:00",
                              key1=("true", "2025-01-01T00:00:00+00:00"), key2=("true", "2024-02-14T08:00:00+00:00")))
    assert [row["Credential"] for row in rows] == ["password", "access_key_1", "access_key_2"]
    assert {row["UserName"] for row in rows} == {"alice"}


def test_root_access_key_is_reported_but_its_password_is_not(fixed_today):
    rows = _age_rows(_age_row("<root_account>", password="not_supported", created=CREATED,
                              key1=("true", "2023-05-10T09:00:00+00:00")))
    assert rows == [{"UserName": "<root_account>", "Credential": "access_key_1",
                     "LastRotated": "2023-05-10T09:00:00+00:00", "AgeDays": 1291}]


def test_age_threshold_comes_from_rule_params(fixed_today):
    rule = dict(AGE_RULE, params={"max_age_days": 90})
    rows = _age_rows(_age_row("alice", changed="2026-06-01T12:30:00+00:00"), rule=rule)  # 173 días
    assert [(row["UserName"], row["AgeDays"]) for row in rows] == [("alice", 173)]
    assert _age_rows(_age_row("alice", changed="2026-06-01T12:30:00+00:00")) == []  # con 365 no


# --- Regla IAM credenciales que caducan pronto (checks.py) ---

EXPIRY_RULE = next(rule for rule in RULES if rule["id"] == "iam-credentials-expiring-soon")
# Con TODAY = 2026-11-21 y max_age_days = 365, una key rotada el 2025-11-30 caduca el 2026-11-30 (9 días).


def _expiring(*rows, rule=EXPIRY_RULE):
    return _age_rows(*rows, rule=rule)


def test_expiry_rule_has_expected_risk_and_params():
    assert EXPIRY_RULE["risk"] == "low"
    assert EXPIRY_RULE["params"]["warning_days"] == 15
    assert EXPIRY_RULE["params"]["max_age_days"] == 365


def test_passwords_expiring_in_less_than_warning_days(fixed_today):
    rows = _expiring(
        _age_row("alice", next_rotation="2026-11-25T12:30:00+00:00"),  # 4 días: aviso
        _age_row("bob", next_rotation="2026-12-06T00:00:00+00:00"),    # 15 días: aún no
        _age_row("carol", next_rotation="2026-11-20T00:00:00+00:00"),  # ya caducada: no
        _age_row("dave", next_rotation="N/A"),                         # la cuenta no caduca contraseñas
        _age_row("erin", next_rotation="2026-11-21T08:00:00+00:00"),   # caduca hoy: aviso
    )
    assert rows == [
        {"UserName": "alice", "Credential": "password", "ExpiresOn": "2026-11-25", "DaysLeft": 4},
        {"UserName": "erin", "Credential": "password", "ExpiresOn": "2026-11-21", "DaysLeft": 0},
    ]


def test_access_keys_expire_at_max_age_after_rotation(fixed_today):
    rows = _expiring(
        _age_row("deploy", password="false", key2=("true", "2025-12-03T16:45:00+00:00")),   # 12 días: aviso
        _age_row("ci", password="false", key1=("false", "2025-12-03T00:00:00+00:00")),      # desactivada: no
        _age_row("old", password="false", key1=("true", "2025-06-01T00:00:00+00:00")),      # ya superó 365 días: no
        _age_row("fresh", password="false", key1=("true", "2026-10-01T00:00:00+00:00")),    # caduca en 314 días: no
    )
    assert rows == [{"UserName": "deploy", "Credential": "access_key_2", "ExpiresOn": "2026-12-03", "DaysLeft": 12}]


def test_root_access_key_is_reported_but_its_password_is_not(fixed_today):
    rows = _expiring(_age_row("<root_account>", password="not_supported",
                              key1=("true", "2025-11-30T09:00:00+00:00")))
    assert rows == [{"UserName": "<root_account>", "Credential": "access_key_1",
                     "ExpiresOn": "2026-11-30", "DaysLeft": 9}]


def test_expiry_warning_and_max_age_come_from_rule_params(fixed_today):
    rows = [
        _age_row("alice", next_rotation="2026-12-06T00:00:00+00:00"),                      # 15 días
        _age_row("deploy", password="false", key1=("true", "2026-09-21T00:00:00+00:00")),  # caduca el 2026-12-20
    ]
    rule = dict(EXPIRY_RULE, params={"warning_days": 30, "max_age_days": 90})
    result = _expiring(*rows, rule=rule)
    assert [(row["UserName"], row["DaysLeft"]) for row in result] == [("alice", 15), ("deploy", 29)]
    assert _expiring(*rows) == []  # con 15 y 365 días no hay avisos
