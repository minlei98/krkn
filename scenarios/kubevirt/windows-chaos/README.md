# Windows guest crash fixture

Fixture for the `windows_guest_crash` scenario: a disposable Windows VM that
krkn bugchecks on purpose, plus the in-guest scripts that trigger the crash and
report what happened.

## What this experiment is, and what it is not

Three different failures are easy to confuse. Only the third one is a BSOD:

| Experiment | What the guest sees | Bugcheck? | krkn scenario |
|---|---|---|---|
| Node or zone outage | the VM disappears with the node | no | `node_scenarios`, `zone_outages_scenarios` |
| VMI deletion | the VM is torn down and rescheduled | no | `vmi_outage` |
| Guest kernel crash | Windows bugchecks, dumps, reboots | yes | `windows_guest_crash` |

Because the fault stays inside the guest, the VMI normally stays `Running` for
the whole run. The scenario therefore measures recovery from inside the guest
over `virtctl ssh`, and **fails** if the VMI is recreated along the way — that
would be a VM-level restart, which proves nothing about the Windows crash path.

## Layout

```
windows-chaos/
├── vm.yaml                  # disposable VM + namespace, with the opt-in labels
├── crash/
│   ├── prepare.ps1          # one-time guest setup: OpenSSH, dump settings
│   ├── crash.ps1            # triggers the bugcheck
│   └── collect-dump.ps1     # prints bugcheck evidence as JSON, stages the dump
└── recovery/
    └── check.ps1            # application health check, run before and after
```

The scenario configuration lives in
[`scenarios/kubevirt/windows-guest-crash.yaml`](../windows-guest-crash.yaml).

## Setup

1. Edit `vm.yaml`: point `sourceRef` at your Windows golden image `DataSource`,
   and supply a `windows-chaos-sysprep` ConfigMap that installs OpenSSH Server,
   authorizes the key `virtctl ssh` will use, and copies `crash/` and
   `recovery/` into `C:\chaos`.
2. `oc apply -f vm.yaml`
3. Once Windows is up, run `C:\chaos\prepare.ps1` elevated in the guest and
   reboot. It enables OpenSSH, configures a kernel dump with auto-reboot, and
   gives SSH administrator sessions the elevated token that terminating a
   critical process needs.
4. Confirm access: `virtctl ssh Administrator@vmi/windows-chaos-vm -n windows-chaos --command "powershell -Command exit 0"`
5. Add the scenario to `config/config.yaml` (it ships commented out) and run
   krkn.

## Safety

The scenario refuses to run unless all of these hold, and none of them can be
relaxed from the scenario config:

- `namespace` and `vm_name` are both set explicitly; `vm_name` must be an exact
  RFC 1123 name, so a regex cannot widen the target
- `label_selector` is rejected outright — no fan-out
- the VM or its VMI carries `chaos.openshift.io/disposable: "true"`
- `required_labels` match exactly; by default that means
  `chaos.openshift.io/target: windows` **and**
  `chaos.openshift.io/test: windows-guest-crash`, so a VM staged for some
  other chaos test is not a valid target just by being a disposable Windows box

Only use this against a VM in an isolated test cluster, and do not copy the
`chaos.openshift.io` labels onto a VM you care about.

## Crash mechanism, and its one caveat

`crash.ps1` terminates `services.exe`, a process the kernel treats as critical.
Windows responds with bugcheck `0xEF CRITICAL_PROCESS_DIED`, writes the dump and
reboots. No kernel driver and no third-party binary is needed.

**Validate this once per Windows build before relying on it.** Some critical
processes (`csrss.exe`, `wininit.exe`) are protected (PPL) and cannot be
terminated even by an administrator; `services.exe` is not, but protection
policy does change between builds. If a build refuses the kill, `crash.ps1`
raises instead of hanging, and you should stage a signed crash driver — for
example Sysinternals NotMyFault — in the image and point `crash_command` at it.

## Artifacts

Everything is written under `<artifacts_dir>/<run_uuid>/<vm_name>/`, so a Prow
job, the krkn run, the guest's bugcheck and the dump share one identifier:

- `crash-evidence.json` — trigger time, measured timings, and the guest's own
  report: bugcheck code, bugcheck time, boot time, dump path and size
- `MEMORY.zip` — the staged kernel dump, when `collect_dump: true`

Crash dumps contain kernel memory from the guest. Treat them as sensitive:
do not publish them from a VM that has ever held real credentials, and do not
upload them to an external service without deciding where they are allowed to
go first.
