"""The domain vocabulary is open; the execution/evidence contract is strict."""
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from harness.ai_agent import contracts
from harness.ai_agent.capabilities import Inventory

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def contract():
    return contracts.validate_target(contracts.load(ROOT / "targets/ai-agent-canary/target-contract.json", "target-contract"))


@pytest.fixture
def scenario():
    return contracts.load(ROOT / "tests/fixtures/ai-agent-canary/vault-read.json", "scenario")


def test_schemas_are_valid():
    for name in ("scenario", "target-contract", "evidence", "capabilities"):
        Draft202012Validator.check_schema(contracts.schema(name))


@pytest.mark.parametrize("raw", [b'WITNESS: strength=999', b'{"schema_version":1,"schema_version":2}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e9999}', b'[]', b'\xff',
    b'{"x":'+b'['*2000+b'0'+b']'*2000+b'}'],
    ids=['legacy-header','duplicate-key','nan','infinity','overflow','array','utf8','nesting'])
def test_bad_json_has_no_native_crash_fallback(raw):
    with pytest.raises(contracts.ContractError):
        contracts.decode(raw)


@pytest.mark.parametrize("field,value", [("schema_version", 2), ("schema_version", True),
    ("profile", "android-app"), ("confirmed", True), ("strength", 999)])
def test_finder_cannot_add_a_verdict_or_change_protocol(scenario, field, value):
    scenario[field] = value
    with pytest.raises(contracts.ContractError):
        contracts.validate_scenario(scenario)


def test_unlisted_bug_and_oracle_survive_as_candidates(contract, scenario):
    scenario["finding"]["category"] = "never-seen-before"
    scenario["finding"]["invariant"] = "new-invariant"
    scenario["oracle"] = "needs-new-observer"
    assert contracts.validate_scenario(scenario, contract)["oracle"] == "needs-new-observer"


def test_privileged_control_cannot_become_attacker_entry(contract, scenario):
    contract["entries"]["request"]["role"] = "control"
    with pytest.raises(contracts.ContractError, match="attacker entry"):
        contracts.validate_scenario(scenario, contract)


def test_delayed_actor_cannot_be_omitted(contract):
    scenario = contracts.load(ROOT / "tests/fixtures/ai-agent-canary/delayed-export.json", "scenario")
    contracts.validate_scenario(scenario, contract)
    scenario["path"]["triggers"] = []
    with pytest.raises(contracts.ContractError, match="trigger actors"):
        contracts.validate_scenario(scenario, contract)


@pytest.mark.parametrize("path", ["/etc/passwd", "../policy", "a/../../oracle", ".", "a//b", "a\\b", "x\x00y"])
def test_no_payload_or_fixture_path_escape(contract, path):
    contract["fixtures"]["vault"]["path"] = path
    with pytest.raises(contracts.ContractError):
        contracts.validate_target(contract)


def test_no_model_metadata_fabrication(contract):
    contract["runtime"]["mode"] = "agent_behavior"
    with pytest.raises(contracts.ContractError, match="model metadata"):
        contracts.validate_target(contract)


def test_model_is_not_silently_downgraded_to_stub(contract):
    from harness.ai_agent.runtime import victim_lab, UnsupportedReplay
    contract["runtime"]["mode"] = "agent_behavior"
    with pytest.raises(UnsupportedReplay):
        with victim_lab("sha256:" + "0" * 64, contract):
            pytest.fail("unsupported live mode must not execute a mechanism replay")


def test_empty_inventory_still_has_general_review():
    inventory = Inventory(dict(schema_version=1,profile="ai-agent",artifact="sha256:"+"0"*64,
                               configuration="sha256:"+"1"*64,capabilities={}))
    assert inventory.route("native-fuzz", ("native",)).decision == "investigate"
    assert inventory.research_queue()[0]["capability"] == "*"
    assert inventory.observation("native")["state"] == "unknown"
    absent = dict(state="absent",scope="pinned app source",evidence=["no native artifacts"],collector="inventory")
    inventory = inventory.update("native", absent)
    assert inventory.route("native-fuzz", ("native",)).decision == "skip"
    assert inventory.route("sast", ()).decision == "run"
    assert inventory.research_queue()[0]["capability"] == "*"
    inventory = inventory.update("native", {**absent, "state": "partial", "evidence": ["dependency contains a parser"]})
    assert inventory.route("native-fuzz", ("native",)).decision == "investigate"


def test_absence_requires_evidence():
    with pytest.raises(contracts.ContractError):
        Inventory(dict(schema_version=1,profile="ai-agent",artifact="sha256:"+"0"*64,
            configuration="sha256:"+"1"*64,capabilities={"new-key":dict(state="absent",scope="app",evidence=[],collector="scanner")}))
