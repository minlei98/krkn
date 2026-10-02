# Copyright 2026 The Krkn Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Windows Guest Crash Scenario Plugin

Triggers a Windows *guest kernel* bugcheck (BSOD) inside a single, explicitly
designated, disposable KubeVirt VM and measures how long the guest takes to
write its crash dump, reboot and become healthy again.

This is deliberately *not* the same experiment as `vmi_outage`:

    vmi_outage          deletes the VMI          -> VM-level restart, no bugcheck
    node/zone outage    removes the hypervisor   -> VM disappears, no bugcheck
    windows_guest_crash crashes the guest kernel -> bugcheck, dump, guest reboot

Because the fault stays inside the guest, the VMI normally stays in `Running`
for the whole run. Recovery is therefore observed from *inside* the guest
(SSH reachability) and not from the VMI phase, and a VMI that gets recreated
during the run fails the scenario: that would be a VM-level restart, which
proves nothing about guest bugcheck recovery.

Safety model (all gates fail closed):

* the target must be named explicitly - no regex, no label-selector fan-out
* the namespace must be set explicitly - there is no default
* the VM or VMI must carry `chaos.openshift.io/disposable: "true"`; this gate
  cannot be switched off from the scenario config
* any additional `required_labels` must match exactly

The crash is triggered by an in-guest script that must be staged in the image
beforehand (see `scenarios/kubevirt/windows-chaos/`). The plugin never ships a
crash payload of its own and never crashes the node or the hypervisor.

Example configuration: `scenarios/kubevirt/windows-guest-crash.yaml`
"""

import json
import logging
import os
import re
import shlex
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import yaml
from krkn_lib.k8s import KrknKubernetes
from krkn_lib.models.k8s import AffectedVMI, VmisStatus
from krkn_lib.models.telemetry import ScenarioTelemetry
from krkn_lib.telemetry.ocp import KrknTelemetryOpenshift
from krkn_lib.utils import log_exception

from krkn.invoke.command import invoke_no_exit
from krkn.scenario_plugins.abstract_scenario_plugin import AbstractScenarioPlugin

# Opt-in label that a VM must carry before this plugin will crash it. Enforced
# unconditionally: it is the only thing standing between a chaos run and an
# arbitrary Windows VM that happens to match the rest of the configuration.
DISPOSABLE_LABEL = "chaos.openshift.io/disposable"
DISPOSABLE_LABEL_VALUE = "true"

# Default additional labels, overridable through `required_labels`.
DEFAULT_REQUIRED_LABELS = {"chaos.openshift.io/target": "windows"}

# RFC 1123 label: also rejects the regex metacharacters that would turn an
# exact target name into a fan-out.
VM_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")

GUEST_OK = "KRKN_GUEST_OK"
GUEST_FAIL = "KRKN_GUEST_FAIL"

PROBE_COMMAND = "powershell -NoProfile -NonInteractive -Command exit 0"
DEFAULT_CRASH_COMMAND = (
    r"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
    r"-File C:\chaos\crash.ps1"
)
DEFAULT_COLLECT_COMMAND = (
    r"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
    r"-File C:\chaos\collect-dump.ps1"
)
DEFAULT_HEALTH_COMMAND = (
    r"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
    r"-File C:\chaos\check.ps1"
)
DEFAULT_STAGE_DIR = r"C:\chaos\artifacts"

EVIDENCE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class TargetValidationError(Exception):
    """Raised when the configured target cannot be verified as a safe target."""


class GuestCrashError(Exception):
    """Raised when the crash, the recovery or the evidence collection fails."""


class WindowsGuestCrashScenarioPlugin(AbstractScenarioPlugin):
    """
    Crashes the Windows kernel of one designated disposable KubeVirt VM and
    verifies that the guest bugchecks, writes a dump and recovers on its own.

    No rollback callable is registered: the scenario creates no cluster-side
    resource and mutates no VM spec, and recovery is the guest rebooting
    itself, which is the behaviour under test rather than something krkn should
    undo. When recovery does not happen the scenario fails loudly and says so,
    leaving the guest untouched for inspection.
    """

    def __init__(self, scenario_type: str = None):
        super().__init__(self.get_scenario_types()[0])
        self.k8s_client: Optional[KrknKubernetes] = None

    def get_scenario_types(self) -> list[str]:
        return ["windows_guest_crash"]

    def run(
        self,
        run_uuid: str,
        scenario: str,
        lib_telemetry: KrknTelemetryOpenshift,
        scenario_telemetry: ScenarioTelemetry,
    ) -> int:
        """
        Entry point: runs every `windows_guest_crash` block of the scenario file.

        :param run_uuid: the uuid of the chaos run, propagated to the artifacts
        :param scenario: path of the scenario configuration file
        :param lib_telemetry: krkn-lib composite telemetry object
        :param scenario_telemetry: telemetry of the scenario being executed
        :return: 0 if every targeted guest crashed and recovered, 1 otherwise
        """
        try:
            with open(scenario, "r") as f:
                scenario_config = yaml.safe_load(f)

            self.k8s_client = lib_telemetry.get_lib_kubernetes()

            configs = [
                config
                for config in (scenario_config or {}).get("scenarios", [])
                if config.get("scenario") in self.get_scenario_types()
            ]
            if not configs:
                logging.error(
                    f"no '{self.get_scenario_types()[0]}' scenario found in {scenario}"
                )
                return 1

            vmis_status = VmisStatus()
            for config in configs:
                self.execute_scenario(run_uuid, config, vmis_status)

            scenario_telemetry.affected_vmis = vmis_status
            return 1 if vmis_status.unrecovered else 0
        except Exception as e:
            logging.error(f"Windows guest crash scenario failed: {e}")
            log_exception(str(e))
            return 1

    def execute_scenario(
        self, run_uuid: str, config: dict[str, Any], vmis_status: VmisStatus
    ) -> None:
        """
        Run a single crash/recover/collect cycle and record its outcome.

        The recorded timings map onto `AffectedVMI` as follows:
          * `vmi_rescheduling_time`: trigger -> guest stopped answering (crash
            propagation)
          * `vmi_readiness_time`: guest stopped answering -> guest answers again
            (bugcheck, dump write and reboot)
          * `total_recovery_time`: trigger -> guest answers again

        :param run_uuid: the uuid of the chaos run, used to namespace artifacts
        :param config: a single scenario block of the scenario file
        :param vmis_status: accumulator the outcome is appended to
        """
        params = config.get("parameters", {}) or {}
        namespace = params.get("namespace")
        vm_name = params.get("vm_name")
        affected_vmi = AffectedVMI(vmi_name=str(vm_name), namespace=str(namespace))

        try:
            vmi = self._validate_target(params)
            self._crash_and_recover(run_uuid, params, affected_vmi, vmi)
        except (TargetValidationError, GuestCrashError) as e:
            logging.error(f"windows guest crash scenario on '{vm_name}' failed: {e}")
            vmis_status.unrecovered.append(affected_vmi)
            return
        except Exception as e:
            logging.error(
                f"unexpected error during windows guest crash scenario "
                f"on '{vm_name}': {e}"
            )
            log_exception(str(e))
            vmis_status.unrecovered.append(affected_vmi)
            return

        vmis_status.recovered.append(affected_vmi)
        logging.info(
            f"VM {vm_name} bugchecked and recovered in "
            f"{affected_vmi.total_recovery_time:.1f}s"
        )

    # -------------------------------------------------------------- targeting

    def _validate_target(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Verify that exactly one explicitly named, explicitly disposable VM is
        being targeted, and that it is running. Every failure is fatal: the
        scenario never falls back to a broader or inferred target.

        :param params: the `parameters` block of the scenario
        :return: the VMI object of the validated target
        :raises TargetValidationError: if the target cannot be verified
        """
        namespace = params.get("namespace")
        vm_name = params.get("vm_name")

        if params.get("label_selector"):
            raise TargetValidationError(
                "label_selector targeting is not supported: a guest crash must "
                "name exactly one disposable VM"
            )
        if not namespace:
            raise TargetValidationError("'namespace' is required and has no default")
        if not vm_name:
            raise TargetValidationError("'vm_name' is required and has no default")
        if not VM_NAME_PATTERN.match(str(vm_name)):
            raise TargetValidationError(
                f"'vm_name' must be an exact RFC 1123 name, got '{vm_name}'"
            )

        vmi = self.k8s_client.get_vmi(vm_name, namespace)
        if not vmi:
            raise TargetValidationError(
                f"VMI {vm_name} not found in namespace {namespace}"
            )

        phase = vmi.get("status", {}).get("phase")
        if phase != "Running":
            raise TargetValidationError(
                f"VMI {vm_name} is in phase '{phase}', expected 'Running'"
            )

        labels = self._target_labels(vm_name, namespace, vmi)
        if labels.get(DISPOSABLE_LABEL) != DISPOSABLE_LABEL_VALUE:
            raise TargetValidationError(
                f"VM {vm_name} is not labelled "
                f"{DISPOSABLE_LABEL}={DISPOSABLE_LABEL_VALUE}; refusing to crash "
                f"a VM that has not explicitly opted in"
            )

        required_labels = params.get("required_labels")
        if required_labels is None:
            required_labels = DEFAULT_REQUIRED_LABELS
        for key, value in required_labels.items():
            if labels.get(key) != str(value):
                raise TargetValidationError(
                    f"VM {vm_name} label '{key}' is '{labels.get(key)}', "
                    f"expected '{value}'"
                )

        logging.info(
            f"validated disposable target VM {vm_name} in namespace {namespace}"
        )
        return vmi

    def _target_labels(
        self, vm_name: str, namespace: str, vmi: dict[str, Any]
    ) -> dict[str, str]:
        """
        Collect the labels of the VM and of its VMI. The opt-in label is
        accepted on either object, because a VM template does not always
        propagate its own labels down to the VMI.

        :param vm_name: exact name of the VM
        :param namespace: namespace of the VM
        :param vmi: the already fetched VMI object
        :return: the merged label map, VMI labels taking precedence
        """
        labels: dict[str, str] = {}
        try:
            vm = self.k8s_client.get_vm(vm_name, namespace)
        except Exception as e:
            # A VMI can exist without a VM; that is not fatal on its own, the
            # label gate below still has to pass on the VMI labels.
            logging.warning(f"could not read VM {vm_name}: {e}")
            vm = None
        if vm:
            labels.update(vm.get("metadata", {}).get("labels", {}) or {})
        labels.update(vmi.get("metadata", {}).get("labels", {}) or {})
        return labels

    # ---------------------------------------------------------------- the run

    def _crash_and_recover(
        self,
        run_uuid: str,
        params: dict[str, Any],
        affected_vmi: AffectedVMI,
        vmi: dict[str, Any],
    ) -> None:
        """
        Baseline, crash, observe recovery, collect evidence, clean up.

        :param run_uuid: the uuid of the chaos run
        :param params: the `parameters` block of the scenario
        :param affected_vmi: filled in with the measured recovery timings
        :param vmi: the validated VMI object, used as the recreation baseline
        :raises GuestCrashError: on any failed step; the guest is left alone so
            that the evidence of the failure survives for manual inspection
        """
        namespace = params["namespace"]
        vm_name = params["vm_name"]
        crash_detect_timeout = params.get("crash_detect_timeout", 120)
        expected_recovery_time = params.get("expected_recovery_time", 300)
        clock_skew_tolerance = params.get("clock_skew_tolerance", 120)
        baseline_uid = vmi.get("metadata", {}).get("uid")

        if not self._guest_reachable(params):
            raise GuestCrashError(
                f"baseline check failed: guest {vm_name} is not reachable over "
                f"virtctl ssh before the crash"
            )
        self._run_health_check(params, stage="baseline")

        crash_started_at = datetime.now(timezone.utc)
        started = time.monotonic()
        logging.info(
            f"[{run_uuid}] triggering guest kernel crash on {vm_name} "
            f"in namespace {namespace}"
        )
        # The SSH session dies with the guest, so a non-zero result here is the
        # expected outcome and carries no information either way.
        self._run_in_guest(
            params,
            params.get("crash_command", DEFAULT_CRASH_COMMAND),
            timeout=params.get("crash_command_timeout", 30),
        )

        down_after = self._wait_for_guest(
            params, reachable=False, timeout=crash_detect_timeout
        )
        if down_after is None:
            raise GuestCrashError(
                f"guest {vm_name} was still reachable {crash_detect_timeout}s "
                f"after the trigger: the crash did not take effect"
            )
        logging.info(f"guest {vm_name} stopped answering after {down_after:.1f}s")

        up_after = self._wait_for_guest(
            params, reachable=True, timeout=expected_recovery_time
        )
        if up_after is None:
            raise GuestCrashError(
                f"guest {vm_name} did not become reachable again within "
                f"{expected_recovery_time}s; manual recovery may be needed"
            )

        total = time.monotonic() - started
        affected_vmi.vmi_rescheduling_time = down_after
        affected_vmi.vmi_readiness_time = up_after
        affected_vmi.total_recovery_time = total

        self._assert_vmi_not_recreated(vm_name, namespace, baseline_uid)

        # Evidence first: cleanup below is allowed to delete the staged dump.
        evidence = self._collect_evidence(run_uuid, params)
        self._assert_bugcheck_is_fresh(evidence, crash_started_at, clock_skew_tolerance)
        self._write_evidence(
            run_uuid, params, evidence, crash_started_at, affected_vmi
        )
        if params.get("collect_dump", True):
            self._fetch_dump(run_uuid, params, evidence)

        self._run_health_check(params, stage="post-recovery")

        if params.get("cleanup", True):
            self._cleanup_guest(params)

    def _assert_vmi_not_recreated(
        self, vm_name: str, namespace: str, baseline_uid: Optional[str]
    ) -> None:
        """
        Fail if the VMI object was replaced while the guest was down. A new VMI
        means the VM itself restarted, which is a `vmi_outage`-shaped event and
        does not demonstrate guest bugcheck recovery.

        :param vm_name: exact name of the VM
        :param namespace: namespace of the VM
        :param baseline_uid: uid of the VMI observed before the crash
        :raises GuestCrashError: if the uid changed or the VMI disappeared
        """
        vmi_after = self.k8s_client.get_vmi(vm_name, namespace)
        current_uid = (vmi_after or {}).get("metadata", {}).get("uid")
        if current_uid != baseline_uid:
            raise GuestCrashError(
                f"VMI {vm_name} was recreated during the run "
                f"(uid {baseline_uid} -> {current_uid}): this was a VM-level "
                f"restart, not a guest-only bugcheck"
            )

    # ------------------------------------------------------------- in a guest

    def _virtctl_ssh_command(self, params: dict[str, Any], command: str) -> str:
        """
        Build the `virtctl ssh` invocation that runs `command` in the guest.

        :param params: the `parameters` block of the scenario
        :param command: the command line to run inside the Windows guest
        :return: the shell command line to execute locally
        """
        connect_timeout = params.get("ssh_connect_timeout", 10)
        parts = [
            "virtctl",
            "ssh",
            "-n",
            shlex.quote(params["namespace"]),
            "--local-ssh-opts=" + shlex.quote("-o BatchMode=yes"),
            "--local-ssh-opts=" + shlex.quote("-o StrictHostKeyChecking=no"),
            "--local-ssh-opts=" + shlex.quote(f"-o ConnectTimeout={connect_timeout}"),
        ]
        identity_file = params.get("ssh_identity_file")
        if identity_file:
            parts += ["--identity-file", shlex.quote(identity_file)]
        user = params.get("ssh_user", "Administrator")
        parts.append(shlex.quote(f"{user}@vmi/{params['vm_name']}"))
        parts.append("--command=" + shlex.quote(command))
        return " ".join(parts)

    def _run_in_guest(
        self,
        params: dict[str, Any],
        command: str,
        timeout: int,
        capture_stderr: bool = True,
    ) -> tuple[bool, str]:
        """
        Run a command inside the guest over `virtctl ssh`.

        :param params: the `parameters` block of the scenario
        :param command: the command line to run inside the Windows guest
        :param timeout: seconds to wait before giving up on the whole invocation
        :param capture_stderr: fold stderr into the output so that failures are
            diagnosable; turn it off when the output has to be parsed, since
            `invoke_no_exit` otherwise discards stderr entirely
        :return: (True if the command exited 0, the raw local output)
        """
        redirect = " 2>&1" if capture_stderr else ""
        full_command = (
            f"{self._virtctl_ssh_command(params, command)}{redirect} "
            f"&& echo {GUEST_OK} || echo {GUEST_FAIL}"
        )
        output = invoke_no_exit(full_command, timeout=timeout)
        return GUEST_OK in output, output

    def _guest_reachable(self, params: dict[str, Any]) -> bool:
        """
        Probe whether the Windows guest answers SSH and can run a command.

        :param params: the `parameters` block of the scenario
        :return: True when the probe command ran successfully in the guest
        """
        timeout = params.get("ssh_probe_timeout", 20)
        reachable, _ = self._run_in_guest(params, PROBE_COMMAND, timeout=timeout)
        return reachable

    def _wait_for_guest(
        self, params: dict[str, Any], reachable: bool, timeout: int
    ) -> Optional[float]:
        """
        Poll the guest until it reaches the wanted reachability state.

        :param params: the `parameters` block of the scenario
        :param reachable: the state to wait for
        :param timeout: how long to wait, in seconds
        :return: the elapsed seconds, or None if the state was never reached
        """
        poll_interval = params.get("poll_interval", 5)
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if self._guest_reachable(params) == reachable:
                return time.monotonic() - started
            time.sleep(poll_interval)
        return None

    def _run_health_check(self, params: dict[str, Any], stage: str) -> None:
        """
        Run the configured in-guest application health check.

        :param params: the `parameters` block of the scenario
        :param stage: 'baseline' or 'post-recovery', used in the message
        :raises GuestCrashError: if the health check reports failure
        """
        command = params.get("health_check_command", DEFAULT_HEALTH_COMMAND)
        if not command:
            logging.info(f"no health check configured, skipping {stage} check")
            return
        healthy, output = self._run_in_guest(
            params, command, timeout=params.get("health_check_timeout", 60)
        )
        if not healthy:
            raise GuestCrashError(
                f"{stage} application health check failed on "
                f"{params['vm_name']}: {output.strip()}"
            )
        logging.info(f"{stage} application health check passed")

    # -------------------------------------------------------------- evidence

    def _collect_evidence(
        self, run_uuid: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Ask the guest for its bugcheck metadata, and stage the dump when the
        scenario asked for it.

        :param run_uuid: the uuid of the chaos run
        :param params: the `parameters` block of the scenario
        :return: the parsed evidence emitted by the in-guest collector
        :raises GuestCrashError: if the collector failed or emitted no JSON
        """
        stage_dir = params.get("stage_dir", DEFAULT_STAGE_DIR)
        command = params.get("collect_dump_command", DEFAULT_COLLECT_COMMAND)
        command = f"{command} -StageDir {stage_dir}"
        if params.get("collect_dump", True):
            command = f"{command} -IncludeDump"

        ok, output = self._run_in_guest(
            params,
            command,
            timeout=params.get("collect_timeout", 300),
            capture_stderr=False,
        )
        if not ok:
            raise GuestCrashError(
                f"crash evidence collection failed on {params['vm_name']}: "
                f"{output.strip()}"
            )

        evidence = self._parse_evidence(output)
        evidence["runUuid"] = run_uuid
        return evidence

    @staticmethod
    def _parse_evidence(output: str) -> dict[str, Any]:
        """
        Extract the single JSON object the in-guest collector prints.

        :param output: raw output of the collector invocation
        :return: the parsed object
        :raises GuestCrashError: if no JSON object could be parsed
        """
        start = output.find("{")
        end = output.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise GuestCrashError(
                f"crash evidence collector returned no JSON: {output.strip()}"
            )
        try:
            return json.loads(output[start : end + 1])
        except ValueError as e:
            raise GuestCrashError(f"crash evidence is not valid JSON: {e}")

    @staticmethod
    def _assert_bugcheck_is_fresh(
        evidence: dict[str, Any],
        crash_started_at: datetime,
        clock_skew_tolerance: int,
    ) -> None:
        """
        Verify that the guest really bugchecked during this run, rather than
        merely rebooting or replaying an old dump.

        :param evidence: the parsed in-guest evidence
        :param crash_started_at: UTC time at which the trigger was sent
        :param clock_skew_tolerance: seconds of guest/runner clock skew allowed
        :raises GuestCrashError: if no bugcheck or only a stale one was found
        """
        raw = evidence.get("bugCheckTimeUtc")
        if not raw:
            raise GuestCrashError(
                "the guest rebooted but reported no bugcheck event: the guest "
                "kernel did not crash"
            )
        try:
            bugcheck_time = datetime.strptime(raw, EVIDENCE_TIME_FORMAT).replace(
                tzinfo=timezone.utc
            )
        except ValueError as e:
            raise GuestCrashError(f"unparsable bugCheckTimeUtc '{raw}': {e}")

        earliest = crash_started_at - timedelta(seconds=clock_skew_tolerance)
        if bugcheck_time < earliest:
            raise GuestCrashError(
                f"the newest bugcheck in the guest is from {raw}, before this "
                f"run started ({crash_started_at.strftime(EVIDENCE_TIME_FORMAT)}): "
                f"the reboot was not caused by this scenario"
            )
        logging.info(
            f"confirmed guest bugcheck {evidence.get('bugCheckCode', 'unknown')} "
            f"at {raw}"
        )

    def _artifacts_dir(self, run_uuid: str, params: dict[str, Any]) -> str:
        """
        Build and create the per-run, per-VM artifacts directory.

        :param run_uuid: the uuid of the chaos run
        :param params: the `parameters` block of the scenario
        :return: the local directory path
        """
        base = params.get("artifacts_dir", "/tmp/krkn-windows-guest-crash")
        path = os.path.join(base, run_uuid, params["vm_name"])
        os.makedirs(path, exist_ok=True)
        return path

    def _write_evidence(
        self,
        run_uuid: str,
        params: dict[str, Any],
        evidence: dict[str, Any],
        crash_started_at: datetime,
        affected_vmi: AffectedVMI,
    ) -> None:
        """
        Persist the correlated evidence next to the dump, keyed by run uuid so
        that a Prow job, the VM events and the dump can be tied together later.

        :param run_uuid: the uuid of the chaos run
        :param params: the `parameters` block of the scenario
        :param evidence: the parsed in-guest evidence
        :param crash_started_at: UTC time at which the trigger was sent
        :param affected_vmi: the measured recovery timings
        """
        record = {
            "runUuid": run_uuid,
            "namespace": params["namespace"],
            "vmName": params["vm_name"],
            "crashTriggeredAtUtc": crash_started_at.strftime(EVIDENCE_TIME_FORMAT),
            "crashDetectionSeconds": affected_vmi.vmi_rescheduling_time,
            "guestRebootSeconds": affected_vmi.vmi_readiness_time,
            "totalRecoverySeconds": affected_vmi.total_recovery_time,
            "guest": evidence,
        }
        path = os.path.join(self._artifacts_dir(run_uuid, params), "crash-evidence.json")
        with open(path, "w") as f:
            json.dump(record, f, indent=2, sort_keys=True)
        logging.info(f"wrote crash evidence to {path}")

    def _fetch_dump(
        self, run_uuid: str, params: dict[str, Any], evidence: dict[str, Any]
    ) -> None:
        """
        Copy the staged crash dump out of the guest with `virtctl scp`.

        A failure here is logged but not fatal: the recovery measurement and the
        bugcheck evidence already stand on their own, and dumps are large enough
        that a transfer failure should not invalidate the run.

        :param run_uuid: the uuid of the chaos run
        :param params: the `parameters` block of the scenario
        :param evidence: the parsed in-guest evidence, holding `stagedPath`
        """
        staged_path = evidence.get("stagedPath")
        if not staged_path:
            logging.warning(
                "the guest staged no dump file; only the bugcheck metadata was "
                "collected"
            )
            return

        local_dir = self._artifacts_dir(run_uuid, params)
        local_path = os.path.join(local_dir, os.path.basename(staged_path.replace("\\", "/")))
        user = params.get("ssh_user", "Administrator")
        parts = [
            "virtctl",
            "scp",
            "-n",
            shlex.quote(params["namespace"]),
            "--local-ssh-opts=" + shlex.quote("-o BatchMode=yes"),
            "--local-ssh-opts=" + shlex.quote("-o StrictHostKeyChecking=no"),
        ]
        identity_file = params.get("ssh_identity_file")
        if identity_file:
            parts += ["--identity-file", shlex.quote(identity_file)]
        parts.append(
            shlex.quote(f"{user}@vmi/{params['vm_name']}:{staged_path}")
        )
        parts.append(shlex.quote(local_path))
        command = (
            f"{' '.join(parts)} && echo {GUEST_OK} || echo {GUEST_FAIL}"
        )

        output = invoke_no_exit(command, timeout=params.get("dump_fetch_timeout", 900))
        if GUEST_OK in output:
            logging.info(f"retrieved crash dump to {local_path}")
        else:
            logging.error(
                f"failed to retrieve the crash dump from {params['vm_name']}; it "
                f"is still staged in the guest at {staged_path}"
            )

    def _cleanup_guest(self, params: dict[str, Any]) -> None:
        """
        Remove the staged artifacts from the guest. Best effort: the VM is
        disposable, so a leftover staging directory is not worth failing a run.

        :param params: the `parameters` block of the scenario
        """
        stage_dir = params.get("stage_dir", DEFAULT_STAGE_DIR)
        command = (
            f"powershell -NoProfile -NonInteractive -Command "
            f"Remove-Item -Recurse -Force -ErrorAction SilentlyContinue {stage_dir}"
        )
        ok, output = self._run_in_guest(
            params, command, timeout=params.get("cleanup_timeout", 60)
        )
        if ok:
            logging.info(f"removed staged artifacts from {stage_dir}")
        else:
            logging.warning(
                f"could not clean up {stage_dir} on {params['vm_name']}: "
                f"{output.strip()}"
            )
