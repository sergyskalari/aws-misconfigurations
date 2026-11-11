import botocore.session
import pytest
import yaml
from botocore.stub import Stubber

from engine import RULES_DIR, filter_rules, load_rules, run_rule

SESSION = botocore.session.get_session()
RULES = load_rules()
EXAMPLE_RULE = next(rule for rule in RULES if rule["id"] == "ec2-sg-open-ssh")


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule["id"])
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
