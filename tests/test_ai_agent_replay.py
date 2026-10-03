"""Observer orchestration tests. These do not substitute for Docker replay."""
import contextlib
import copy
import json
import sys
from pathlib import Path

import pytest

from harness.ai_agent import contracts, evidence, runtime

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def setup(monkeypatch):
    contract = contracts.load(ROOT / "targets/ai-agent-canary/target-contract.json", "target-contract")
    scenario = contracts.load(ROOT / "tests/fixtures/ai-agent-canary/vault-read.json", "scenario")
    monkeypatch.setattr(runtime, "image_identity", lambda image: "sha256:" + "a" * 64)
    labs = []

    class Lab:
        def __init__(self, index):
            self.fixtures = {"vault": f"unpredictable-vault-{index}", "owner-token": f"owner-{index}"}
            self.pending = False
            self.requests = []

        def execute(self, entry, request):
            self.requests.append((entry, request))
            op = request.get("operation")
            if op == "vault.read":
                content = self.fixtures["vault"]
            elif op == "export.enqueue":
                self.pending = True
                content = "queued"
            elif op == "export.run":
                content = self.fixtures["vault"] if self.pending else "no pending export"
            else:
                content = "public"
            return runtime.CommandResult(0, json.dumps({"content":content}).encode(), b"", 1.0)

    @contextlib.contextmanager
    def lab(image, contract):
        current = Lab(len(labs))
        labs.append(current)
        yield current

    monkeypatch.setattr(runtime, "victim_lab", lab)
    return contract, scenario, labs, Lab


def test_fresh_controls_and_attack_trials_and_checkable_observations(setup):
    contract, scenario, labs, _ = setup
    result = runtime.replay(scenario, contract, "test-image")
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.confirmed and (outcome.successes, outcome.completed, outcome.scheduled) == (3,3,3)
    assert len(labs) == 15  # four separate controls plus a fresh attack per trial
    assert len({lab.fixtures['vault'] for lab in labs}) == 15
    assert result['observations'][0]['value'] == labs[4].fixtures['vault']
    assert labs[0].requests[0][1]['token'] == labs[0].fixtures['owner-token']
    assert 'token' not in labs[4].requests[0][1]  # credentials never supplied to candidate


def test_self_reported_marker_and_finder_claims_do_not_confirm(setup):
    contract, scenario, _, _ = setup
    scenario['steps'][0]['input'] = {'operation':'public.info','content':'unpredictable-vault-4',
                                    'confirmed':True,'strength':999}
    outcome = evidence.assess(runtime.replay(scenario, contract, 'image'), scenario, contract)
    assert outcome.disposition == 'not_observed'


def test_component_replay_does_not_inherit_finder_shipping_scope(setup):
    contract, scenario, _, _ = setup
    contract['entries']['request']['scope'] = 'component'
    outcome = evidence.assess(runtime.replay(scenario, contract, 'image'), scenario, contract)
    assert outcome.disposition == 'component_only'


def test_unknown_oracle_is_unresolved_and_never_executes(setup):
    contract, scenario, labs, _ = setup
    scenario['oracle'] = 'novel-mechanism'
    outcome = evidence.assess(runtime.replay(scenario, contract, 'image'), scenario, contract)
    assert outcome.disposition == 'unresolved' and outcome.completed == 0
    assert not labs


def test_controls_fail_closed_when_service_disabled(setup, monkeypatch):
    contract, scenario, _, Lab = setup
    monkeypatch.setattr(Lab, 'execute', lambda *args: runtime.CommandResult(0,b'{"content":"disabled"}',b'',1))
    result = runtime.replay(scenario, contract, 'image')
    assert evidence.assess(result, scenario, contract).disposition == 'unresolved'
    assert all(t['status'] == 'infrastructure_error' for t in result['trials'])


def test_one_violation_plus_infrastructure_failure_keeps_denominators(setup, monkeypatch):
    contract, scenario, labs, Lab = setup
    original = Lab.execute
    def fail_second_trial(self, entry, request):
        if len(labs) > 5:
            raise runtime.ReplayError('service unavailable')
        return original(self, entry, request)
    monkeypatch.setattr(Lab, 'execute', fail_second_trial)
    result = runtime.replay(scenario, contract, 'image')
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.confirmed and (outcome.successes,outcome.completed,outcome.scheduled) == (1,1,3)
    assert len(result['trials']) == 3


@pytest.mark.parametrize('mutation', ['controls','hash','scope','wrong-ref','trial-count','duplicate-observation','fake-claim'])
def test_corrupted_evidence_cannot_be_promoted(setup, mutation):
    contract, scenario, _, _ = setup
    result = runtime.replay(scenario, contract, 'image')
    if mutation=='controls': result['controls']=[]
    elif mutation=='hash': result['scenario_digest']='sha256:'+'b'*64
    elif mutation=='scope': result['scope']='static_path'; contract['entries']['request']['scope']='component'
    elif mutation=='wrong-ref': result['trials'][0]['observation_ids']=['unknown']
    elif mutation=='trial-count': result['trials'].pop()
    elif mutation=='duplicate-observation': result['observations'].append(copy.deepcopy(result['observations'][0]))
    elif mutation=='fake-claim': result['confirmed']=True
    with pytest.raises(contracts.ContractError):
        evidence.assess(result, scenario, contract)


def test_unknown_observation_is_not_implicitly_native_crash(setup):
    contract, scenario, _, _ = setup
    result = runtime.replay(scenario, contract, 'image')
    result['observations'][0]['kind']='new-unimplemented-observation'
    assert evidence.assess(result, scenario, contract).disposition == 'unresolved'


def test_bounded_process_handles_binary_io_and_nonzero_exit():
    result = runtime.bounded_command([sys.executable,'-c',
        'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write("error"); sys.exit(7)'],
        payload=b'\x00hello'*10000, limit=100000)
    assert result.stdout == b'\x00hello'*10000 and result.returncode == 7 and result.stderr == b'error'


def test_output_budget_enforced_during_execution():
    with pytest.raises(runtime.ReplayError, match='byte budget'):
        runtime.bounded_command([sys.executable,'-c','import os\nwhile True: os.write(1,b"x"*8192)'],limit=4096)


def test_time_budget_enforced():
    with pytest.raises(runtime.ReplayError, match='time budget'):
        runtime.bounded_command([sys.executable,'-c','import time; time.sleep(10)'],timeout=0.1)
