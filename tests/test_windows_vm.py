import json
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from argparse import Namespace
from pathlib import Path
from unittest import mock

from haloce_catalog import cli as catalog_cli
from haloce_catalog.windows_vm import (
    WINDOWS_VM_BUNDLE_FORMAT,
    WindowsVmConfig,
    check_vfio_host,
    generate_windows_vm_bundle,
    qmp_events_from_input_trace,
    replay_qmp_input_events,
    run_windows_guest_trace,
)
from haloce_catalog.target import target_config_from_mapping


class WindowsVmTests(unittest.TestCase):
    def test_generate_windows_vm_bundle_writes_declarative_guest_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = WindowsVmConfig(
                name="halo-test",
                disk_path=root / "disk.qcow2",
                windows_iso=root / "windows.iso",
                autounattend_iso=root / "autounattend.iso",
                virtio_iso=root / "virtio.iso",
                spice_tools_iso=root / "spice.iso",
                shared_dir=root / "share",
                ovmf_code=root / "OVMF_CODE.fd",
                ovmf_vars=root / "OVMF_VARS.fd",
                ovmf_vars_template=root / "OVMF_VARS.template.fd",
                qmp_socket=root / "qmp.sock",
                dynamorio_root=root / "DynamoRIO-Windows",
                trace_client_dll=root / "halo_trace.dll",
                halo_runtime_root=root / "HaloRuntime",
                virtio_tools_root=root / "VirtioWin",
                spice_tools_root=root / "SpiceWin",
                gpu_pci_addresses=("0000:2d:00.0",),
                usb_vendor_products=("046d:c539",),
                xorriso="/nix/store/test-xorriso/bin/xorriso",
            )

            result = generate_windows_vm_bundle(config, root / "bundle")

            self.assertEqual(result["format"], WINDOWS_VM_BUNDLE_FORMAT)
            self.assertEqual(result["display"]["mode"], "spice-qxl")
            self.assertEqual(result["display"]["gpu_pci_addresses"], ["0000:2d:00.0"])
            paths = result["paths"]
            xml = ET.parse(paths["domain_xml"]).getroot()
            self.assertEqual(xml.findtext("name"), "halo-test")
            self.assertTrue((root / "share").is_dir())
            self.assertIsNotNone(xml.find("memoryBacking/access[@mode='shared']"))
            self.assertEqual(xml.findtext("os/loader"), str(root / "OVMF_CODE.fd"))
            self.assertEqual(xml.find("os/nvram").attrib["template"], str(root / "OVMF_VARS.template.fd"))
            self.assertEqual([boot.attrib["dev"] for boot in xml.findall("os/boot")], ["hd", "cdrom"])
            self.assertIsNotNone(xml.find("devices/graphics[@type='spice']"))
            self.assertIsNotNone(xml.find("devices/interface/model[@type='virtio']"))
            self.assertIsNotNone(xml.find("devices/filesystem/driver[@type='virtiofs']"))
            self.assertIsNotNone(xml.find("devices/channel/target[@name='org.qemu.guest_agent.0']"))
            self.assertIsNotNone(xml.find("devices/hostdev[@type='pci']"))
            self.assertIsNotNone(xml.find("devices/hostdev[@type='usb']"))

            autounattend = Path(paths["autounattend_xml"]).read_text(encoding="utf-8")
            first_logon = Path(paths["first_logon_ps1"]).read_text(encoding="utf-8")
            guest_trace = Path(paths["guest_trace_ps1"]).read_text(encoding="utf-8")
            host_trace = Path(paths["trace_script"]).read_text(encoding="utf-8")
            host_prove_trace = Path(paths["prove_trace_script"]).read_text(encoding="utf-8")
            qmp_replay = Path(paths["qmp_replay_script"]).read_text(encoding="utf-8")
            define_script = Path(paths["define_script"]).read_text(encoding="utf-8")
            snapshot_script = Path(paths["snapshot_script"]).read_text(encoding="utf-8")
            staging_iso = Path(paths["staging_iso_script"]).read_text(encoding="utf-8")
            readme = Path(paths["readme"]).read_text(encoding="utf-8")
            manifest = json.loads(Path(paths["staging_manifest"]).read_text(encoding="utf-8"))

        self.assertIn("first-logon.ps1", autounattend)
        self.assertIn("windowsPE", autounattend)
        self.assertIn("DiskConfiguration", autounattend)
        self.assertIn(r"%configsetroot%\$WinPEDriver$", autounattend)
        self.assertIn("Get-PSDrive", autounattend)
        self.assertNotIn("-File D:\\first-logon.ps1", autounattend)
        self.assertIn("Enable-PSRemoting", first_logon)
        self.assertIn("first-logon-transcript.txt", first_logon)
        self.assertIn(r"NetKVM\2k25\amd64\netkvm.inf", first_logon)
        self.assertIn("pnputil.exe", first_logon)
        self.assertIn("OpenSSH.Server", first_logon)
        self.assertIn("DynamoRIO-Windows-*.zip", first_logon)
        self.assertIn(r"bin32\drrun.exe", first_logon)
        self.assertIn("HaloRuntime", first_logon)
        self.assertIn(r"bin32\drrun.exe", guest_trace)
        self.assertIn('[string]$Target = "Dedicated"', guest_trace)
        self.assertIn("haloceded.exe", guest_trace)
        self.assertIn("timed_out = $TimedOut", guest_trace)
        self.assertIn("exit_code = $ExitCode", guest_trace)
        self.assertIn('target="${4:-Dedicated}"', host_trace)
        self.assertIn("HALOCE_WINDOWS_VM_PASSWORD", host_trace)
        self.assertIn("--password \"$password\"", host_trace)
        self.assertIn("prove-windows-guest-trace", host_prove_trace)
        self.assertIn('target="${6:-Dedicated}"', host_prove_trace)
        self.assertIn("--report-dir \"$report_dir\"", host_prove_trace)
        self.assertIn("HALOCE_WINDOWS_VM_SKIP_REPORTS", host_prove_trace)
        self.assertIn("replay-qmp-input", qmp_replay)
        self.assertIn("--domain halo-test", qmp_replay)
        self.assertIn("--virsh-uri qemu:///system", qmp_replay)
        self.assertIn("virsh -c qemu:///system define", define_script)
        self.assertIn("virsh -c qemu:///system snapshot-create-as", snapshot_script)
        self.assertIn("remote-viewer spice://127.0.0.1", readme)
        self.assertIn("-as mkisofs", staging_iso)
        self.assertIn("/nix/store/test-xorriso/bin/xorriso", staging_iso)
        self.assertIn("chmod -R u+w", staging_iso)
        self.assertIn("VirtioWin", staging_iso)
        self.assertIn(r"\$WinPEDriver\$", staging_iso)
        self.assertIn("SpiceWin", staging_iso)
        self.assertIn("HALOTRACE", staging_iso)
        self.assertEqual(manifest["format"], WINDOWS_VM_BUNDLE_FORMAT)
        self.assertEqual(manifest["xorriso"], "/nix/store/test-xorriso/bin/xorriso")
        self.assertEqual(manifest["staging_iso_contents"][-1]["destination"], "SpiceWin")

    def test_generate_windows_vm_bundle_uses_manifest_vm_defaults_for_generic_targets(self):
        target = target_config_from_mapping(
            {
                "project": {"id": "toy-vm", "name": "Toy VM Target"},
                "trace_targets": [
                    {
                        "id": "startup",
                        "executable": "toy.exe",
                        "expected_filename": "toy.exe",
                        "args": ["--smoke"],
                    }
                ],
                "windows_vm": {
                    "trace_root": r"C:\ToyTrace",
                    "runtime_dir": "ToyRuntime",
                    "runtime_stage_dir": "Payload",
                    "guest_trace_script": "Run-ToyTrace.ps1",
                    "trace_client_name": "toy_trace.dll",
                    "iso_volume_id": "TOYTRACE",
                    "admin_user": "toyuser",
                    "admin_password": "ToyPassword!",
                    "password_env": "TOY_WINDOWS_VM_PASSWORD",
                    "skip_reports_env": "TOY_WINDOWS_VM_SKIP_REPORTS",
                    "default_trace_target": "startup",
                },
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = WindowsVmConfig(
                name="toy-vm",
                disk_path=root / "disk.qcow2",
                autounattend_iso=root / "autounattend.iso",
                shared_dir=root / "share",
                runtime_root=root / "Runtime",
                target_config=target,
            )

            result = generate_windows_vm_bundle(config, root / "bundle")
            first_logon = Path(result["paths"]["first_logon_ps1"]).read_text(encoding="utf-8")
            guest_trace = Path(result["paths"]["guest_trace_ps1"]).read_text(encoding="utf-8")
            host_trace = Path(result["paths"]["trace_script"]).read_text(encoding="utf-8")
            host_prove = Path(result["paths"]["prove_trace_script"]).read_text(encoding="utf-8")
            staging_iso = Path(result["paths"]["staging_iso_script"]).read_text(encoding="utf-8")
            manifest = json.loads(Path(result["paths"]["staging_manifest"]).read_text(encoding="utf-8"))

        self.assertIn('[string]$Target = "startup"', guest_trace)
        self.assertIn('target="${4:-startup}"', host_trace)
        self.assertIn("TOY_WINDOWS_VM_PASSWORD", host_trace)
        self.assertIn("TOY_WINDOWS_VM_SKIP_REPORTS", host_prove)
        self.assertIn('cp -R "$runtime_root" "$stage_dir/Payload"', staging_iso)
        self.assertEqual(
            [item["destination"] for item in manifest["staging_iso_contents"] if item["source"]],
            ["Autounattend.xml", "first-logon.ps1", "Run-ToyTrace.ps1", "Payload"],
        )
        for text in (first_logon, host_trace, host_prove, staging_iso):
            self.assertNotIn("HaloRuntime", text)
            self.assertNotIn("HALOCE_WINDOWS_VM", text)

    def test_generate_windows_vm_bundle_can_disable_emulated_video_for_gpu_traces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = WindowsVmConfig(
                name="halo-gpu",
                disk_path=root / "disk.qcow2",
                autounattend_iso=root / "autounattend.iso",
                shared_dir=root / "share",
                ovmf_code=root / "OVMF_CODE.fd",
                ovmf_vars=root / "OVMF_VARS.fd",
                ovmf_vars_template=root / "OVMF_VARS.template.fd",
                qmp_socket=root / "qmp.sock",
                gpu_pci_addresses=("0000:12:00.0", "0000:12:00.1"),
                display_mode="gpu-only",
            )

            result = generate_windows_vm_bundle(config, root / "bundle")
            xml = ET.parse(result["paths"]["domain_xml"]).getroot()
            readme = Path(result["paths"]["readme"]).read_text(encoding="utf-8")

        self.assertEqual(result["display"]["mode"], "gpu-only")
        self.assertEqual(result["display"]["gpu_pci_addresses"], ["0000:12:00.0", "0000:12:00.1"])
        self.assertIsNone(xml.find("devices/graphics"))
        self.assertIsNone(xml.find("devices/channel/target[@name='com.redhat.spice.0']"))
        self.assertIsNotNone(xml.find("devices/video/model[@type='none']"))
        self.assertEqual(len(xml.findall("devices/hostdev[@type='pci']")), 2)
        self.assertNotIn("remote-viewer", readme)

    def test_gpu_only_display_requires_passthrough_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = WindowsVmConfig(
                name="halo-gpu",
                disk_path=root / "disk.qcow2",
                autounattend_iso=root / "autounattend.iso",
                shared_dir=root / "share",
                display_mode="gpu-only",
            )

            with self.assertRaises(ValueError):
                generate_windows_vm_bundle(config, root / "bundle")

    def test_qmp_events_from_input_trace_maps_keyboard_mouse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.jsonl"
            records = [
                {"kind": "session", "format": "haloce-input-trace-v1"},
                {"kind": "event", "t": 0.0, "type": 1, "code_name": "KEY_W", "value": 1},
                {"kind": "event", "t": 0.1, "type": 1, "code_name": "KEY_W", "value": 0},
                {"kind": "event", "t": 0.2, "type": 2, "code_name": "REL_X", "value": 12},
                {"kind": "event", "t": 0.3, "type": 1, "code_name": "BTN_LEFT", "value": 1},
                {"kind": "event", "t": 0.4, "type": 1, "code_name": "KEY_UNKNOWN", "value": 1},
            ]
            path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

            events = qmp_events_from_input_trace(path)

        self.assertEqual(len(events), 4)
        self.assertEqual(events[0]["qmp"]["arguments"]["events"][0]["data"]["key"]["data"], "w")
        self.assertTrue(events[0]["qmp"]["arguments"]["events"][0]["data"]["down"])
        self.assertFalse(events[1]["qmp"]["arguments"]["events"][0]["data"]["down"])
        self.assertEqual(events[2]["qmp"]["arguments"]["events"][0]["data"]["axis"], "x")
        self.assertEqual(events[3]["qmp"]["arguments"]["events"][0]["data"]["button"], "left")

    def test_replay_qmp_input_dry_run_and_virsh_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "qmp.jsonl"
            commands = [
                {
                    "t": 0.0,
                    "qmp": {
                        "execute": "input-send-event",
                        "arguments": {"events": [{"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": "w"}}}]},
                    },
                },
                {
                    "t": 0.25,
                    "qmp": {
                        "execute": "input-send-event",
                        "arguments": {"events": [{"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": "w"}}}]},
                    },
                },
            ]
            path.write_text("\n".join(json.dumps(command) for command in commands) + "\n", encoding="utf-8")

            dry_run = replay_qmp_input_events(path, dry_run=True)
            with (
                mock.patch("haloce_catalog.windows_vm.time.sleep") as sleep,
                mock.patch(
                    "haloce_catalog.windows_vm.subprocess.run",
                    return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout='{"return":{}}\n', stderr=""),
                ) as run,
            ):
                result = replay_qmp_input_events(path, domain="halo-test", speed=2.0)

        self.assertEqual(dry_run["events"], 2)
        self.assertEqual(dry_run["duration_seconds"], 0.25)
        self.assertEqual(result["backend"], "virsh")
        self.assertEqual(result["sent"], 2)
        self.assertTrue(result["ok"])
        sleep.assert_called_once_with(0.125)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0][:4], ["virsh", "-c", "qemu:///system", "qemu-monitor-command"])
        self.assertEqual(run.call_args_list[0].args[0][4], "halo-test")

    def test_run_windows_guest_trace_can_use_generated_password_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "logs"
            completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")
            with mock.patch("haloce_catalog.windows_vm.subprocess.run", return_value=completed) as run:
                result = run_windows_guest_trace(
                    host="192.0.2.10",
                    user="halo",
                    out_dir=out_dir,
                    target="Client",
                    run_seconds=5,
                    test_id_prefix="trace-client",
                    password="secret",
                    sshpass="/bin/sshpass",
                    ssh="/bin/ssh",
                    scp="/bin/scp",
                )

        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 2)
        ssh_command = run.call_args_list[0].args[0]
        scp_command = run.call_args_list[1].args[0]
        self.assertEqual(ssh_command[:3], ["/bin/sshpass", "-p", "secret"])
        self.assertIn("PubkeyAuthentication=no", ssh_command)
        self.assertIn("PreferredAuthentications=password", ssh_command)
        self.assertIn("halo@192.0.2.10", ssh_command)
        self.assertIn("-Target Client", ssh_command[-1])
        self.assertEqual(scp_command[:3], ["/bin/sshpass", "-p", "secret"])
        self.assertIn("halo@192.0.2.10:C:/HaloTrace/logs/trace-client-client.result.json", scp_command)

    def test_prove_windows_guest_trace_uses_dedicated_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_dir = root / "logs"
            out_dir.mkdir()
            (out_dir / "trace-dedicated.result.json").write_text(
                json.dumps({"timed_out": True, "exit_code": -1}),
                encoding="utf-8",
            )
            args = Namespace(
                db=root / "catalog.db",
                host="192.0.2.10",
                user="halo",
                out_dir=out_dir,
                target="Dedicated",
                run_seconds=5,
                test_id_prefix="trace",
                expected_filename=None,
                expected_sha256=None,
                trace_log=None,
                suite="windows-vm-dedicated",
                report_dir=root / "reports",
                skip_reports=False,
                fail_on_timeout=False,
                password="secret",
                sshpass="/bin/sshpass",
                ssh="/bin/ssh",
                scp="/bin/scp",
                copy_all_logs=False,
            )
            run_result = {
                "ok": True,
                "ssh_command": ["/bin/ssh", "halo@192.0.2.10"],
                "trace_returncode": 0,
                "stdout": "",
                "stderr": "",
            }
            proof_result = {"ok": True, "failures": []}
            with (
                mock.patch("haloce_catalog.cli.run_windows_guest_trace", return_value=run_result) as run,
                mock.patch("haloce_catalog.cli.prove_halo_trace_log", return_value=proof_result) as prove,
                mock.patch("haloce_catalog.cli.generate_reports", return_value={}),
                mock.patch("haloce_catalog.cli._print_json"),
            ):
                code = catalog_cli._cmd_prove_windows_guest_trace(args)

        self.assertEqual(code, 0)
        run.assert_called_once()
        prove.assert_called_once()
        _, trace_log, test_id = prove.call_args.args[:3]
        self.assertEqual(trace_log, out_dir / "trace-dedicated.jsonl")
        self.assertEqual(test_id, "trace-dedicated")
        self.assertEqual(prove.call_args.kwargs["expected_filename"], "haloceded.exe")
        self.assertTrue(prove.call_args.kwargs["timed_out"])

    def test_check_vfio_host_reports_ready_devices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            devices = root / "devices"
            drivers = root / "drivers"
            groups = root / "groups"
            device = devices / "0000:12:00.0"
            driver = drivers / "vfio-pci"
            group = groups / "29"
            device.mkdir(parents=True)
            driver.mkdir(parents=True)
            group.mkdir(parents=True)
            (device / "driver").symlink_to(driver)
            (device / "iommu_group").symlink_to(group)
            (device / "reset").write_text("", encoding="utf-8")
            (device / "reset_method").write_text("bus\n", encoding="utf-8")
            cmdline = root / "cmdline"
            cmdline.write_text("quiet amd_iommu=on iommu=pt vfio-pci.ids=1002:13c0,1002:1640\n", encoding="utf-8")

            result = check_vfio_host(
                pci_addresses=["12:00.0"],
                required_kernel_params=["amd_iommu=on", "iommu=pt"],
                sysfs_devices_root=devices,
                cmdline_path=cmdline,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["missing_kernel_params"], [])
        self.assertEqual(result["devices"][0]["address"], "0000:12:00.0")
        self.assertEqual(result["devices"][0]["driver"], "vfio-pci")
        self.assertEqual(result["devices"][0]["iommu_group"], "29")
        self.assertEqual(result["devices"][0]["reset_method"], "bus")


if __name__ == "__main__":
    unittest.main()
