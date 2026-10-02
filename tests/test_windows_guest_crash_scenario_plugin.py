#!/usr/bin/env python3

"""
Test suite for the Windows Guest Crash Scenario Plugin.

Everything outside the plugin is mocked: no cluster, no KubeVirt, no virtctl
and no Windows guest are needed. `invoke_no_exit` is replaced by a fake guest
that dispatches on the command line, and the plugin's clock is replaced so that
the recovery waiters resolve deterministically instead of sleeping.

Coverage:
- target scoping and the fail-closed safety gates
- crash outcome detection (guest must actually stop answering)
- recovery success and timeout
- bugcheck evidence freshness, including the VM-level-restart guard
- dump retrieval, evidence file contents and cleanup/error paths

Usage:
    python -m unittest tests.test_windows_guest_crash_scenario_plugin -v

Assisted-by: Claude <noreply@anthropic.com>
"""

import json
import os
import tempfile
import unittest
from collections import deque
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import yaml

from krkn.scenario_plugins.windows_guest_crash import (
    windows_guest_crash_scenario_plugin as plugin_module,
)
from krkn.scenario_plugins.windows_guest_crash.windows_guest_crash_scenario_plugin import (
    GUEST_FAIL,
    GUEST_OK,
    WindowsGuestCrashScenarioPlugin,
)

RUN_UUID = "11111111-2222-3333-4444-555555555555"


def utc_stamp(offset_seconds: int = 0) -> str:
    """Format a timestamp the way the in-guest collector does."""
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return moment.strftime(plugin_module.EVIDENCE_TIME_FORMAT)


class FakeClock:
    """Monotonic clock that only moves when the plugin asks it to."""

    def __init__(self, step: float = 1.0):
        self.now = 0.0
        self.step = step

    def monotonic(self) -> float:
        self.now += self.step
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeGuest:
    """
    Stand-in for `invoke_no_exit`, dispatching on the generated command line.

    :param probe_results: reachability answers, in order; the last one repeats
    :param evidence: object the in-guest collector prints, or None for garbage
    :param health_results: health check answers, in order; the last one repeats
    :param scp_ok: whether the dump transfer succeeds
    """

    def __init__(
        self,
        probe_results=(True, False, True),
        evidence=None,
        health_results=(True,),
        scp_ok=True,
    ):
        self.probe_results = deque(probe_results)
        self.evidence = evidence if evidence is not None else {
            "bugCheckCode": "0x000000ef",
            "bugCheckTimeUtc": utc_stamp(),
            "lastBootUpTimeUtc": utc_stamp(),
            "dumpPath": "C:\\Windows\\MEMORY.DMP",
            "dumpSizeBytes": 1024,
            "stagedPath": "C:\\chaos\\artifacts\\MEMORY.zip",
        }
        self.health_results = deque(health_results)
        self.scp_ok = scp_ok
        self.commands = []

    @staticmethod
    def _next(queue_):
        value = queue_[0] if len(queue_) == 1 else queue_.popleft()
        return value

    def __call__(self, command, timeout=None):
        self.commands.append(command)
        if "virtctl scp" in command:
            return GUEST_OK if self.scp_ok else GUEST_FAIL
        if "crash.ps1" in command:
            return GUEST_FAIL  # the session dies with the guest
        if "collect-dump.ps1" in command:
            if self.evidence is False:
                return f"not json at all\n{GUEST_OK}"
            return f"{json.dumps(self.evidence)}\n{GUEST_OK}"
        if "check.ps1" in command:
            return GUEST_OK if self._next(self.health_results) else GUEST_FAIL
        if "Remove-Item" in command:
            return GUEST_OK
        if "exit 0" in command:
            return GUEST_OK if self._next(self.probe_results) else GUEST_FAIL
        raise AssertionError(f"unexpected command: {command}")

    def ran(self, fragment: str) -> bool:
        return any(fragment in command for command in self.commands)


class TestWindowsGuestCrashScenarioPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = WindowsGuestCrashScenarioPlugin()
        self.k8s_client = MagicMock()
        self.plugin.k8s_client = self.k8s_client

        self.vmi = {
            "metadata": {
                "name": "windows-chaos-vm",
                "namespace": "windows-chaos",
                "uid": "vmi-uid-1",
                "labels": {
                    "chaos.openshift.io/target": "windows",
                    "chaos.openshift.io/disposable": "true",
                    "chaos.openshift.io/test": "windows-guest-crash",
                },
            },
            "status": {"phase": "Running"},
        }
        self.k8s_client.get_vmi.return_value = self.vmi
        self.k8s_client.get_vm.return_value = {"metadata": {"labels": {}}}

        self.artifacts_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.artifacts_dir.cleanup)

        self.clock = FakeClock()
        clock_patch = patch.object(plugin_module, "time", self.clock)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def params(self, **overrides):
        params = {
            "namespace": "windows-chaos",
            "vm_name": "windows-chaos-vm",
            "crash_command": "powershell -File C:\\chaos\\crash.ps1",
            "collect_dump_command": "powershell -File C:\\chaos\\collect-dump.ps1",
            "health_check_command": "powershell -File C:\\chaos\\check.ps1",
            "artifacts_dir": self.artifacts_dir.name,
            "crash_detect_timeout": 30,
            "expected_recovery_time": 60,
            "poll_interval": 5,
        }
        params.update(overrides)
        return params

    def execute(self, guest=None, **overrides):
        """
        Run one scenario block against a fake guest.

        :return: (the VmisStatus accumulator, the fake guest)
        """
        guest = guest or FakeGuest()
        status = plugin_module.VmisStatus()
        config = {"scenario": "windows_guest_crash", "parameters": self.params(**overrides)}
        with patch.object(plugin_module, "invoke_no_exit", guest):
            self.plugin.execute_scenario(RUN_UUID, config, status)
        return status, guest

    def assertFailed(self, status):
        self.assertEqual(0, len(status.recovered))
        self.assertEqual(1, len(status.unrecovered))

    def assertRecovered(self, status):
        self.assertEqual([], status.unrecovered)
        self.assertEqual(1, len(status.recovered))

    # ---------------------------------------------------------- safety gates

    def test_rejects_label_selector(self):
        status, guest = self.execute(label_selector="app=windows")
        self.assertFailed(status)
        self.assertEqual([], guest.commands)

    def test_requires_namespace(self):
        status, guest = self.execute(namespace=None)
        self.assertFailed(status)
        self.assertEqual([], guest.commands)

    def test_requires_vm_name(self):
        status, guest = self.execute(vm_name="")
        self.assertFailed(status)
        self.assertEqual([], guest.commands)

    def test_rejects_regex_vm_name(self):
        for name in (".*", "windows-.*", "win|other", "Windows-VM"):
            with self.subTest(name=name):
                status, guest = self.execute(vm_name=name)
                self.assertFailed(status)
                self.assertEqual([], guest.commands)

    def test_requires_disposable_label(self):
        self.vmi["metadata"]["labels"]["chaos.openshift.io/disposable"] = "false"
        status, guest = self.execute()
        self.assertFailed(status)
        self.assertEqual([], guest.commands)

    def test_disposable_label_cannot_be_waived_by_required_labels(self):
        del self.vmi["metadata"]["labels"]["chaos.openshift.io/disposable"]
        status, _ = self.execute(required_labels={})
        self.assertFailed(status)

    def test_requires_additional_labels_to_match(self):
        self.vmi["metadata"]["labels"]["chaos.openshift.io/target"] = "linux"
        status, _ = self.execute()
        self.assertFailed(status)

    def test_requires_the_approved_test_label_by_default(self):
        del self.vmi["metadata"]["labels"]["chaos.openshift.io/test"]
        status, guest = self.execute()
        self.assertFailed(status)
        self.assertEqual([], guest.commands)

    def test_rejects_a_vm_approved_for_a_different_test(self):
        self.vmi["metadata"]["labels"]["chaos.openshift.io/test"] = "some-other-test"
        status, _ = self.execute()
        self.assertFailed(status)

    def test_accepts_disposable_label_carried_only_by_the_vm(self):
        self.vmi["metadata"]["labels"] = {}
        self.k8s_client.get_vm.return_value = {
            "metadata": {
                "labels": {
                    "chaos.openshift.io/target": "windows",
                    "chaos.openshift.io/disposable": "true",
                    "chaos.openshift.io/test": "windows-guest-crash",
                }
            }
        }
        status, _ = self.execute()
        self.assertRecovered(status)

    def test_fails_when_vmi_is_missing(self):
        self.k8s_client.get_vmi.return_value = None
        status, _ = self.execute()
        self.assertFailed(status)

    def test_fails_when_vmi_is_not_running(self):
        self.vmi["status"]["phase"] = "Scheduling"
        status, _ = self.execute()
        self.assertFailed(status)

    def test_unreadable_vm_does_not_block_a_labelled_vmi(self):
        self.k8s_client.get_vm.side_effect = Exception("forbidden")
        status, _ = self.execute()
        self.assertRecovered(status)

    # ------------------------------------------------------- crash detection

    def test_fails_when_baseline_guest_is_unreachable(self):
        status, guest = self.execute(guest=FakeGuest(probe_results=(False,)))
        self.assertFailed(status)
        self.assertFalse(guest.ran("crash.ps1"))

    def test_fails_when_baseline_health_check_fails(self):
        guest = FakeGuest(probe_results=(True,), health_results=(False,))
        status, guest = self.execute(guest=guest)
        self.assertFailed(status)
        self.assertFalse(guest.ran("crash.ps1"))

    def test_fails_when_the_guest_never_stops_answering(self):
        guest = FakeGuest(probe_results=(True,))
        status, guest = self.execute(guest=guest)
        self.assertFailed(status)
        self.assertTrue(guest.ran("crash.ps1"))
        self.assertFalse(guest.ran("collect-dump.ps1"))

    def test_fails_when_the_guest_never_comes_back(self):
        guest = FakeGuest(probe_results=(True, False))
        status, guest = self.execute(guest=guest)
        self.assertFailed(status)
        self.assertFalse(guest.ran("collect-dump.ps1"))

    # ------------------------------------------------------------- evidence

    def test_fails_when_the_vmi_was_recreated(self):
        recreated = json.loads(json.dumps(self.vmi))
        recreated["metadata"]["uid"] = "vmi-uid-2"
        self.k8s_client.get_vmi.side_effect = [self.vmi, recreated]
        status, guest = self.execute()
        self.assertFailed(status)
        self.assertFalse(guest.ran("collect-dump.ps1"))

    def test_fails_when_the_guest_reports_no_bugcheck(self):
        guest = FakeGuest(evidence={"lastBootUpTimeUtc": utc_stamp()})
        status, _ = self.execute(guest=guest)
        self.assertFailed(status)

    def test_fails_on_a_stale_bugcheck(self):
        guest = FakeGuest(
            evidence={
                "bugCheckCode": "0x000000ef",
                "bugCheckTimeUtc": utc_stamp(-3600),
                "stagedPath": "C:\\chaos\\artifacts\\MEMORY.zip",
            }
        )
        status, _ = self.execute(guest=guest, clock_skew_tolerance=120)
        self.assertFailed(status)

    def test_tolerates_guest_clock_skew_on_the_bugcheck_timestamp(self):
        guest = FakeGuest(
            evidence={
                "bugCheckCode": "0x000000ef",
                "bugCheckTimeUtc": utc_stamp(-90),
                "stagedPath": "C:\\chaos\\artifacts\\MEMORY.zip",
            }
        )
        status, _ = self.execute(guest=guest, clock_skew_tolerance=120)
        self.assertRecovered(status)

    def test_fails_on_unparsable_evidence(self):
        status, _ = self.execute(guest=FakeGuest(evidence=False))
        self.assertFailed(status)

    def test_fails_on_an_unparsable_bugcheck_timestamp(self):
        guest = FakeGuest(evidence={"bugCheckTimeUtc": "last tuesday"})
        status, _ = self.execute(guest=guest)
        self.assertFailed(status)

    # ------------------------------------------------- artifacts and cleanup

    def test_writes_evidence_keyed_by_run_uuid(self):
        status, _ = self.execute()
        self.assertRecovered(status)
        path = os.path.join(
            self.artifacts_dir.name, RUN_UUID, "windows-chaos-vm", "crash-evidence.json"
        )
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            record = json.load(f)
        self.assertEqual(RUN_UUID, record["runUuid"])
        self.assertEqual("windows-chaos-vm", record["vmName"])
        self.assertEqual("0x000000ef", record["guest"]["bugCheckCode"])
        self.assertIsNotNone(record["crashTriggeredAtUtc"])
        self.assertGreater(record["totalRecoverySeconds"], 0)

    def test_records_recovery_timings(self):
        status, _ = self.execute()
        affected = status.recovered[0]
        self.assertGreater(affected.vmi_rescheduling_time, 0)
        self.assertGreater(affected.vmi_readiness_time, 0)
        self.assertGreater(affected.total_recovery_time, 0)

    def test_fetches_the_dump_and_cleans_up(self):
        status, guest = self.execute()
        self.assertRecovered(status)
        self.assertTrue(guest.ran("virtctl scp"))
        self.assertTrue(guest.ran("Remove-Item"))

    def test_collect_dump_false_skips_the_transfer(self):
        status, guest = self.execute(collect_dump=False)
        self.assertRecovered(status)
        self.assertFalse(guest.ran("virtctl scp"))
        self.assertFalse(guest.ran("-IncludeDump"))

    def test_cleanup_false_leaves_the_staged_artifacts(self):
        status, guest = self.execute(cleanup=False)
        self.assertRecovered(status)
        self.assertFalse(guest.ran("Remove-Item"))

    def test_a_failed_dump_transfer_does_not_fail_the_run(self):
        status, guest = self.execute(guest=FakeGuest(scp_ok=False))
        self.assertRecovered(status)
        self.assertTrue(guest.ran("virtctl scp"))

    def test_evidence_is_collected_before_cleanup(self):
        _, guest = self.execute()
        collect = next(i for i, c in enumerate(guest.commands) if "collect-dump.ps1" in c)
        cleanup = next(i for i, c in enumerate(guest.commands) if "Remove-Item" in c)
        self.assertLess(collect, cleanup)

    def test_fails_when_the_post_recovery_health_check_fails(self):
        guest = FakeGuest(health_results=(True, False))
        status, guest = self.execute(guest=guest)
        self.assertFailed(status)
        self.assertTrue(guest.ran("collect-dump.ps1"))

    # ----------------------------------------------------- command rendering

    def test_virtctl_ssh_command_is_scoped_and_quoted(self):
        command = self.plugin._virtctl_ssh_command(
            self.params(ssh_user="Administrator", ssh_identity_file="/tmp/id_rsa"),
            "powershell -Command exit 0",
        )
        self.assertIn("virtctl ssh -n windows-chaos", command)
        self.assertIn("Administrator@vmi/windows-chaos-vm", command)
        self.assertIn("--identity-file /tmp/id_rsa", command)
        self.assertIn("--local-ssh-opts='-o BatchMode=yes'", command)
        self.assertIn("--command='powershell -Command exit 0'", command)

    def test_ssh_user_is_quoted(self):
        command = self.plugin._virtctl_ssh_command(
            self.params(ssh_user="admin; touch /tmp/pwned"), "powershell -Command exit 0"
        )
        self.assertIn("'admin; touch /tmp/pwned@vmi/windows-chaos-vm'", command)

    def test_in_guest_command_arguments_cannot_break_out_of_quoting(self):
        command = self.plugin._virtctl_ssh_command(
            self.params(), "whoami'; rm -rf /tmp/pwned; echo '"
        )
        self.assertNotIn("rm -rf /tmp/pwned;", command.split("--command=")[0])
        self.assertIn("--command=", command)

    # ------------------------------------------------------------------ run

    def test_run_returns_zero_on_success(self):
        exit_code, telemetry, guest = self.run_scenario_file()
        self.assertEqual(0, exit_code)
        self.assertEqual(1, len(telemetry.affected_vmis.recovered))
        self.assertTrue(guest.ran("crash.ps1"))

    def test_run_returns_one_on_failure(self):
        exit_code, telemetry, _ = self.run_scenario_file(
            guest=FakeGuest(probe_results=(False,))
        )
        self.assertEqual(1, exit_code)
        self.assertEqual(1, len(telemetry.affected_vmis.unrecovered))

    def test_run_returns_one_when_the_file_holds_no_matching_scenario(self):
        exit_code, _, guest = self.run_scenario_file(
            document={"scenarios": [{"scenario": "vmi_outage", "parameters": {}}]}
        )
        self.assertEqual(1, exit_code)
        self.assertEqual([], guest.commands)

    def test_run_returns_one_on_a_missing_scenario_file(self):
        telemetry = plugin_module.ScenarioTelemetry()
        lib_telemetry = MagicMock()
        lib_telemetry.get_lib_kubernetes.return_value = self.k8s_client
        exit_code = self.plugin.run(
            RUN_UUID, "/nonexistent/scenario.yaml", lib_telemetry, telemetry
        )
        self.assertEqual(1, exit_code)

    def run_scenario_file(self, guest=None, document=None):
        """
        Drive the plugin through its public `run()` entry point.

        :return: (exit code, the scenario telemetry, the fake guest)
        """
        guest = guest or FakeGuest()
        document = document or {
            "scenarios": [
                {"scenario": "windows_guest_crash", "parameters": self.params()}
            ]
        }
        telemetry = plugin_module.ScenarioTelemetry()
        lib_telemetry = MagicMock()
        lib_telemetry.get_lib_kubernetes.return_value = self.k8s_client

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(document, f)
            path = f.name
        self.addCleanup(os.unlink, path)

        with patch.object(plugin_module, "invoke_no_exit", guest):
            exit_code = self.plugin.run(RUN_UUID, path, lib_telemetry, telemetry)
        return exit_code, telemetry, guest


if __name__ == "__main__":
    unittest.main()
