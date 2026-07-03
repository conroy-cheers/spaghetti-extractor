from __future__ import annotations

import json
import shlex
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .input_trace import iter_input_trace
from .target import TargetConfig, TraceTarget, load_target_config
from .util import json_dumps, utc_now


WINDOWS_VM_BUNDLE_FORMAT = "wincr-windows-vm-bundle-v1"
QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"
UNATTEND_NS = "urn:schemas-microsoft-com:unattend"
WCM_NS = "http://schemas.microsoft.com/WMIConfig/2002/State"


@dataclass(frozen=True)
class WindowsVmConfig:
    name: str = "haloce-wintrace"
    memory_mib: int = 8192
    vcpus: int = 4
    disk_path: Path = Path("private/windows-vm/haloce-wintrace.qcow2")
    windows_iso: Path | None = None
    autounattend_iso: Path = Path("build/windows-vm/autounattend.iso")
    virtio_iso: Path | None = None
    spice_tools_iso: Path | None = None
    shared_dir: Path = Path("private/windows-vm/share")
    ovmf_code: Path = Path("/run/libvirt/nix-ovmf/edk2-x86_64-code.fd")
    ovmf_vars: Path = Path("private/windows-vm/OVMF_VARS.fd")
    ovmf_vars_template: Path = Path("/run/libvirt/nix-ovmf/edk2-x86_64-vars.fd")
    qmp_socket: Path = Path("build/windows-vm/qmp.sock")
    admin_user: str = "halo"
    admin_password: str = "ChangeMe-HaloTrace-LocalOnly!"
    dynamorio_root: Path | None = None
    trace_client_dll: Path | None = None
    runtime_root: Path | None = None
    halo_runtime_root: Path | None = None
    virtio_tools_root: Path | None = None
    spice_tools_root: Path | None = None
    install_image_index: int = 1
    gpu_pci_addresses: tuple[str, ...] = ()
    usb_vendor_products: tuple[str, ...] = ()
    display_mode: str = "spice-qxl"
    network: str = "default"
    libvirt_uri: str = "qemu:///system"
    xorriso: str = "xorriso"
    target_config: TargetConfig = field(default_factory=load_target_config)


def generate_windows_vm_bundle(config: WindowsVmConfig, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    share_dir = config.shared_dir
    share_dir.mkdir(parents=True, exist_ok=True)
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "domain_xml": out_dir / f"{config.name}.xml",
        "autounattend_xml": out_dir / "Autounattend.xml",
        "first_logon_ps1": out_dir / "first-logon.ps1",
        "guest_trace_ps1": out_dir / config.target_config.windows_vm.guest_trace_script,
        "staging_manifest": out_dir / "staging-manifest.json",
        "define_script": scripts_dir / "define-vm.sh",
        "snapshot_script": scripts_dir / "snapshot-create.sh",
        "revert_script": scripts_dir / "snapshot-revert.sh",
        "trace_script": scripts_dir / "run-guest-trace.sh",
        "prove_trace_script": scripts_dir / "prove-guest-trace.sh",
        "qmp_replay_script": scripts_dir / "replay-qmp-input.sh",
        "staging_iso_script": scripts_dir / "build-staging-iso.sh",
        "readme": out_dir / "README.md",
    }

    paths["domain_xml"].write_text(render_libvirt_domain_xml(config), encoding="utf-8")
    paths["autounattend_xml"].write_text(render_autounattend_xml(config), encoding="utf-8")
    paths["first_logon_ps1"].write_text(render_first_logon_script(config), encoding="utf-8")
    paths["guest_trace_ps1"].write_text(render_guest_trace_script(config.target_config), encoding="utf-8")
    paths["staging_manifest"].write_text(json_dumps(_staging_manifest(config, out_dir)) + "\n", encoding="utf-8")
    paths["define_script"].write_text(_define_script(paths["domain_xml"], config.libvirt_uri), encoding="utf-8")
    paths["snapshot_script"].write_text(_snapshot_script(config.name, config.libvirt_uri), encoding="utf-8")
    paths["revert_script"].write_text(_revert_script(config.name, config.libvirt_uri), encoding="utf-8")
    paths["trace_script"].write_text(_host_trace_shell_script(config.name, config.target_config), encoding="utf-8")
    paths["prove_trace_script"].write_text(_host_prove_trace_shell_script(config.name, config.target_config), encoding="utf-8")
    paths["qmp_replay_script"].write_text(_qmp_replay_shell_script(config.name, config.libvirt_uri), encoding="utf-8")
    paths["staging_iso_script"].write_text(_staging_iso_script(config, out_dir), encoding="utf-8")
    paths["readme"].write_text(render_bundle_readme(config, out_dir, paths), encoding="utf-8")
    for script in (
        "define_script",
        "snapshot_script",
        "revert_script",
        "trace_script",
        "prove_trace_script",
        "qmp_replay_script",
        "staging_iso_script",
    ):
        paths[script].chmod(0o755)

    return {
        "format": WINDOWS_VM_BUNDLE_FORMAT,
        "created_at": utc_now(),
        "vm_name": config.name,
        "out_dir": str(out_dir),
        "shared_dir": str(share_dir),
        "paths": {key: str(value) for key, value in paths.items()},
        "firmware": {
            "ovmf_code": str(config.ovmf_code),
            "ovmf_vars": str(_xml_path(config.ovmf_vars)),
            "ovmf_vars_template": str(config.ovmf_vars_template),
        },
        "private_inputs": {
            "windows_iso": _path_or_none(config.windows_iso),
            "virtio_iso": _path_or_none(config.virtio_iso),
            "spice_tools_iso": _path_or_none(config.spice_tools_iso),
            "dynamorio_root": _path_or_none(config.dynamorio_root),
            "trace_client_dll": _path_or_none(config.trace_client_dll),
            "runtime_root": _path_or_none(_runtime_root(config)),
            "halo_runtime_root": _path_or_none(config.halo_runtime_root),
            "virtio_tools_root": _path_or_none(config.virtio_tools_root),
            "spice_tools_root": _path_or_none(config.spice_tools_root),
        },
        "libvirt_uri": config.libvirt_uri,
        "display": {
            "mode": config.display_mode,
            "gpu_pci_addresses": list(config.gpu_pci_addresses),
            "usb_vendor_products": list(config.usb_vendor_products),
        },
    }


def render_libvirt_domain_xml(config: WindowsVmConfig) -> str:
    ET.register_namespace("qemu", QEMU_NS)
    domain = ET.Element("domain", {"type": "kvm"})
    ET.SubElement(domain, "name").text = config.name
    ET.SubElement(domain, "memory", {"unit": "MiB"}).text = str(config.memory_mib)
    ET.SubElement(domain, "currentMemory", {"unit": "MiB"}).text = str(config.memory_mib)
    memory_backing = ET.SubElement(domain, "memoryBacking")
    ET.SubElement(memory_backing, "source", {"type": "memfd"})
    ET.SubElement(memory_backing, "access", {"mode": "shared"})
    ET.SubElement(domain, "vcpu", {"placement": "static"}).text = str(config.vcpus)

    os_el = ET.SubElement(domain, "os")
    ET.SubElement(os_el, "type", {"arch": "x86_64", "machine": "pc-q35-11.0"}).text = "hvm"
    ET.SubElement(os_el, "loader", {"readonly": "yes", "type": "pflash"}).text = str(config.ovmf_code)
    ET.SubElement(os_el, "nvram", {"template": str(config.ovmf_vars_template)}).text = str(_xml_path(config.ovmf_vars))
    ET.SubElement(os_el, "boot", {"dev": "hd"})
    ET.SubElement(os_el, "boot", {"dev": "cdrom"})

    features = ET.SubElement(domain, "features")
    for name in ("acpi", "apic"):
        ET.SubElement(features, name)
    hyperv = ET.SubElement(features, "hyperv", {"mode": "custom"})
    for name in ("relaxed", "vapic", "spinlocks"):
        attrs = {"state": "on"}
        if name == "spinlocks":
            attrs["retries"] = "8191"
        ET.SubElement(hyperv, name, attrs)

    ET.SubElement(domain, "cpu", {"mode": "host-passthrough", "check": "none", "migratable": "on"})
    ET.SubElement(domain, "clock", {"offset": "localtime"})
    ET.SubElement(domain, "on_poweroff").text = "destroy"
    ET.SubElement(domain, "on_reboot").text = "restart"
    ET.SubElement(domain, "on_crash").text = "restart"

    devices = ET.SubElement(domain, "devices")
    ET.SubElement(devices, "emulator").text = "/run/current-system/sw/bin/qemu-system-x86_64"
    _add_disk(devices, config.disk_path, "vda", "virtio", "disk", readonly=False)
    if config.windows_iso is not None:
        _add_disk(devices, config.windows_iso, "sda", "sata", "cdrom", readonly=True)
    _add_disk(devices, config.autounattend_iso, "sdb", "sata", "cdrom", readonly=True)
    if config.virtio_iso is not None:
        _add_disk(devices, config.virtio_iso, "sdc", "sata", "cdrom", readonly=True)
    if config.spice_tools_iso is not None:
        _add_disk(devices, config.spice_tools_iso, "sdd", "sata", "cdrom", readonly=True)

    interface = ET.SubElement(devices, "interface", {"type": "network"})
    ET.SubElement(interface, "source", {"network": config.network})
    ET.SubElement(interface, "model", {"type": "virtio"})

    filesystem = ET.SubElement(devices, "filesystem", {"type": "mount", "accessmode": "passthrough"})
    ET.SubElement(filesystem, "driver", {"type": "virtiofs"})
    ET.SubElement(filesystem, "source", {"dir": str(_xml_path(config.shared_dir))})
    ET.SubElement(filesystem, "target", {"dir": f"{config.target_config.project_id}-trace-share"})

    channel = ET.SubElement(devices, "channel", {"type": "unix"})
    ET.SubElement(channel, "target", {"type": "virtio", "name": "org.qemu.guest_agent.0"})
    if config.display_mode == "spice-qxl":
        spice_channel = ET.SubElement(devices, "channel", {"type": "spicevmc"})
        ET.SubElement(spice_channel, "target", {"type": "virtio", "name": "com.redhat.spice.0"})
        ET.SubElement(devices, "graphics", {"type": "spice", "autoport": "yes", "listen": "127.0.0.1"})
        ET.SubElement(devices, "video").append(ET.Element("model", {"type": "qxl", "ram": "65536", "vram": "65536", "heads": "1"}))
    elif config.display_mode == "gpu-only":
        if not config.gpu_pci_addresses:
            raise ValueError("display_mode='gpu-only' requires at least one --gpu-pci-address")
        ET.SubElement(devices, "video").append(ET.Element("model", {"type": "none"}))
    else:
        raise ValueError(f"unsupported Windows VM display mode: {config.display_mode}")
    ET.SubElement(devices, "input", {"type": "tablet", "bus": "usb"})
    ET.SubElement(devices, "input", {"type": "keyboard", "bus": "usb"})
    ET.SubElement(devices, "memballoon", {"model": "virtio"})
    ET.SubElement(devices, "rng", {"model": "virtio"}).append(ET.Element("backend", {"model": "random"}))

    for pci in config.gpu_pci_addresses:
        _add_pci_hostdev(devices, pci)
    for vendor_product in config.usb_vendor_products:
        _add_usb_hostdev(devices, vendor_product)

    qemu_cmd = ET.SubElement(domain, f"{{{QEMU_NS}}}commandline")
    for value in ("-qmp", f"unix:{_xml_path(config.qmp_socket)},server=on,wait=off"):
        ET.SubElement(qemu_cmd, f"{{{QEMU_NS}}}arg", {"value": value})

    _indent(domain)
    return ET.tostring(domain, encoding="unicode") + "\n"


def render_autounattend_xml(config: WindowsVmConfig) -> str:
    ET.register_namespace("", UNATTEND_NS)
    ET.register_namespace("wcm", WCM_NS)
    unattend = ET.Element(f"{{{UNATTEND_NS}}}unattend")

    windows_pe = ET.SubElement(unattend, "settings", {"pass": "windowsPE"})
    intl = _unattend_component(windows_pe, "Microsoft-Windows-International-Core-WinPE")
    setup_ui = ET.SubElement(intl, "SetupUILanguage")
    ET.SubElement(setup_ui, "UILanguage").text = "en-US"
    for tag in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        ET.SubElement(intl, tag).text = "en-US"

    pnp = _unattend_component(windows_pe, "Microsoft-Windows-PnpCustomizationsWinPE")
    driver_paths = ET.SubElement(pnp, "DriverPaths")
    path_and_credentials = ET.SubElement(
        driver_paths,
        "PathAndCredentials",
        {f"{{{WCM_NS}}}action": "add", f"{{{WCM_NS}}}keyValue": "1"},
    )
    ET.SubElement(path_and_credentials, "Path").text = r"%configsetroot%\$WinPEDriver$"

    setup = _unattend_component(windows_pe, "Microsoft-Windows-Setup")
    disk_configuration = ET.SubElement(setup, "DiskConfiguration")
    disk = ET.SubElement(disk_configuration, "Disk", {f"{{{WCM_NS}}}action": "add"})
    ET.SubElement(disk, "DiskID").text = "0"
    ET.SubElement(disk, "WillWipeDisk").text = "true"
    create_partitions = ET.SubElement(disk, "CreatePartitions")
    _create_partition(create_partitions, 1, "EFI", size=100)
    _create_partition(create_partitions, 2, "MSR", size=16)
    _create_partition(create_partitions, 3, "Primary", extend=True)
    modify_partitions = ET.SubElement(disk, "ModifyPartitions")
    _modify_partition(modify_partitions, 1, 1, "System", "FAT32")
    _modify_partition(modify_partitions, 2, 3, "Windows", "NTFS", letter="C")
    ET.SubElement(disk_configuration, "WillShowUI").text = "OnError"

    image_install = ET.SubElement(setup, "ImageInstall")
    os_image = ET.SubElement(image_install, "OSImage")
    install_from = ET.SubElement(os_image, "InstallFrom")
    metadata = ET.SubElement(install_from, "MetaData", {f"{{{WCM_NS}}}action": "add"})
    ET.SubElement(metadata, "Key").text = "/IMAGE/INDEX"
    ET.SubElement(metadata, "Value").text = str(config.install_image_index)
    install_to = ET.SubElement(os_image, "InstallTo")
    ET.SubElement(install_to, "DiskID").text = "0"
    ET.SubElement(install_to, "PartitionID").text = "3"
    ET.SubElement(os_image, "WillShowUI").text = "OnError"

    user_data = ET.SubElement(setup, "UserData")
    ET.SubElement(user_data, "AcceptEula").text = "true"
    ET.SubElement(user_data, "FullName").text = config.target_config.windows_vm.operator_display_name
    ET.SubElement(user_data, "Organization").text = "Clean Room"

    specialize = ET.SubElement(unattend, "settings", {"pass": "specialize"})
    specialize_shell = _unattend_component(specialize, "Microsoft-Windows-Shell-Setup")
    ET.SubElement(specialize_shell, "ComputerName").text = config.target_config.windows_vm.computer_name
    ET.SubElement(specialize_shell, "TimeZone").text = "UTC"

    settings = ET.SubElement(unattend, "settings", {"pass": "oobeSystem"})
    component = _unattend_component(settings, "Microsoft-Windows-Shell-Setup")
    oobe = ET.SubElement(component, "OOBE")
    ET.SubElement(oobe, "HideEULAPage").text = "true"
    ET.SubElement(oobe, "HideLocalAccountScreen").text = "true"
    ET.SubElement(oobe, "HideOEMRegistrationScreen").text = "true"
    ET.SubElement(oobe, "HideOnlineAccountScreens").text = "true"
    ET.SubElement(oobe, "HideWirelessSetupInOOBE").text = "true"
    ET.SubElement(oobe, "ProtectYourPC").text = "3"

    accounts = ET.SubElement(component, "UserAccounts")
    local_accounts = ET.SubElement(accounts, "LocalAccounts")
    local_account = ET.SubElement(local_accounts, "LocalAccount", {f"{{{WCM_NS}}}action": "add"})
    ET.SubElement(local_account, "Name").text = config.admin_user
    ET.SubElement(local_account, "DisplayName").text = config.target_config.windows_vm.operator_display_name
    ET.SubElement(local_account, "Group").text = "Administrators"
    password = ET.SubElement(local_account, "Password")
    ET.SubElement(password, "Value").text = config.admin_password
    ET.SubElement(password, "PlainText").text = "true"

    autologon = ET.SubElement(component, "AutoLogon")
    auto_password = ET.SubElement(autologon, "Password")
    ET.SubElement(auto_password, "Value").text = config.admin_password
    ET.SubElement(auto_password, "PlainText").text = "true"
    ET.SubElement(autologon, "Enabled").text = "true"
    ET.SubElement(autologon, "LogonCount").text = "2"
    ET.SubElement(autologon, "Username").text = config.admin_user

    first_logon = ET.SubElement(component, "FirstLogonCommands")
    command = ET.SubElement(first_logon, "SynchronousCommand", {"action": "add"})
    ET.SubElement(command, "Order").text = "1"
    ET.SubElement(command, "Description").text = f"Provision {config.target_config.project_name} trace VM"
    first_logon_command = (
        "$Script = Get-PSDrive -PSProvider FileSystem | "
        "ForEach-Object { Join-Path $_.Root 'first-logon.ps1' } | "
        "Where-Object { Test-Path $_ } | Select-Object -First 1; "
        "if (-not $Script) { throw 'first-logon.ps1 not found' }; "
        "& $Script"
    )
    ET.SubElement(command, "CommandLine").text = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass "
        f"-Command \"{first_logon_command}\""
    )

    _indent(unattend)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(unattend, encoding="unicode") + "\n"


def render_first_logon_script(config: WindowsVmConfig) -> str:
    vm = config.target_config.windows_vm
    return f"""# Generated by wincr. Keep this generated media private.
$ErrorActionPreference = "Stop"
$TraceRoot = "{vm.trace_root}"
$DynamoRoot = Join-Path $TraceRoot "DynamoRIO"
$RuntimeRoot = Join-Path $TraceRoot "{vm.runtime_dir}"
$LogRoot = Join-Path $TraceRoot "logs"
New-Item -ItemType Directory -Force -Path $TraceRoot, $DynamoRoot, $RuntimeRoot, $LogRoot | Out-Null
try {{ Start-Transcript -Path (Join-Path $LogRoot "first-logon-transcript.txt") -Append | Out-Null }} catch {{ }}

function Invoke-LoggedNative {{
  param([string]$FilePath, [string[]]$ArgumentList)
  Write-Host "Running $FilePath $($ArgumentList -join ' ')"
  & $FilePath @ArgumentList 2>&1 | ForEach-Object {{ Write-Host $_ }}
  if ($LASTEXITCODE -ne 0) {{
    Write-Warning "$FilePath exited with $LASTEXITCODE"
  }}
  return $LASTEXITCODE
}}

function Install-DriverInf {{
  param([string]$InfPath)
  if (-not (Test-Path $InfPath)) {{ return $false }}
  Invoke-LoggedNative -FilePath "pnputil.exe" -ArgumentList @("/add-driver", $InfPath, "/install") | Out-Null
  return $true
}}

function Start-InstallerWithTimeout {{
  param([string]$FilePath, [string]$ArgumentList, [int]$TimeoutSeconds = 120)
  $Process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru
  if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {{
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    Write-Warning "$FilePath timed out after $TimeoutSeconds seconds"
    return
  }}
  if ($Process.ExitCode -ne 0) {{
    Write-Warning "$FilePath exited with $($Process.ExitCode)"
  }}
}}

try {{
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
}} catch {{
  Write-Warning "Execution policy update skipped: $($_.Exception.Message)"
}}
Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1

$Drives = Get-PSDrive -PSProvider FileSystem | ForEach-Object {{ $_.Root }}
foreach ($Drive in $Drives) {{
  $NetKvmInf = Join-Path $Drive "VirtioWin\\NetKVM\\2k25\\amd64\\netkvm.inf"
  if (Install-DriverInf -InfPath $NetKvmInf) {{ break }}
}}
Start-Sleep -Seconds 3

try {{
  $WinRmService = Get-Service WinRM -ErrorAction SilentlyContinue
  if ($WinRmService -and $WinRmService.Status -eq "Running") {{
    Set-Service WinRM -StartupType Automatic
  }} else {{
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Set-Service WinRM -StartupType Automatic
    Start-Service WinRM
  }}
}} catch {{
  Write-Warning "WinRM setup failed: $($_.Exception.Message)"
}}
try {{
  $OpenSshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  if ($OpenSshCapability.State -ne "Installed") {{
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  }}
}} catch {{
  Write-Warning "OpenSSH capability install failed: $($_.Exception.Message)"
}}
$SshService = Get-Service sshd -ErrorAction SilentlyContinue
if ($SshService) {{
  try {{
    Set-Service sshd -StartupType Automatic
    if ($SshService.Status -ne "Running") {{
      Start-Service sshd
    }}
    if (-not (Get-NetFirewallRule -Name {vm.firewall_rule_name} -ErrorAction SilentlyContinue)) {{
      New-NetFirewallRule -Name {vm.firewall_rule_name} -DisplayName "{vm.firewall_rule_display_name}" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue | Out-Null
    }}
  }} catch {{
    Write-Warning "OpenSSH service start failed: $($_.Exception.Message)"
  }}
}}

foreach ($Drive in $Drives) {{
  $VirtioTools = Join-Path $Drive "virtio-win-guest-tools.exe"
  if (Test-Path $VirtioTools) {{
    Start-InstallerWithTimeout -FilePath $VirtioTools -ArgumentList "/install /quiet /norestart"
  }}
  $SpiceTools = Join-Path $Drive "spice-guest-tools.exe"
  if (Test-Path $SpiceTools) {{
    Start-InstallerWithTimeout -FilePath $SpiceTools -ArgumentList "/S"
  }}
  $DynamoZip = Get-ChildItem -Path $Drive -Filter "DynamoRIO-Windows-*.zip" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($DynamoZip) {{
    Expand-Archive -Path $DynamoZip.FullName -DestinationPath $DynamoRoot -Force
  }}
  $DynamoTree = Join-Path $Drive "DynamoRIO"
  if (Test-Path (Join-Path $DynamoTree "bin32\\drrun.exe")) {{ robocopy $DynamoTree $DynamoRoot /MIR /NFL /NDL /NJH /NJS /NP | Out-Null }}
  $TraceClient = Get-ChildItem -Path $Drive -Filter "{vm.trace_client_name}" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  $TraceClientDest = Join-Path $TraceRoot "{vm.trace_client_name}"
  if ($TraceClient -and $TraceClient.FullName -ne $TraceClientDest) {{ Copy-Item -Force $TraceClient.FullName $TraceClientDest }}
{_powershell_runtime_source_probe(vm)}
  if ($RuntimeSource -and (Test-Path $RuntimeSource)) {{ robocopy $RuntimeSource $RuntimeRoot /MIR /NFL /NDL /NJH /NJS /NP | Out-Null }}
  $GuestTrace = Join-Path $Drive "{vm.guest_trace_script}"
  if (Test-Path $GuestTrace) {{ Copy-Item -Force $GuestTrace (Join-Path $TraceRoot "{vm.guest_trace_script}") }}
}}

$Ready = [ordered]@{{
  ready = $true
  generated_by = "wincr"
  generated_format = "{WINDOWS_VM_BUNDLE_FORMAT}"
  dynamorio = $DynamoRoot
  runtime = $RuntimeRoot
  trace_client = (Join-Path $TraceRoot "{vm.trace_client_name}")
  logs = $LogRoot
  timestamp = (Get-Date).ToUniversalTime().ToString("o")
}}
$Ready | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $TraceRoot "guest-ready.json")
try {{ Stop-Transcript | Out-Null }} catch {{ }}
"""


def render_guest_trace_script(target_config: TargetConfig | None = None) -> str:
    target = target_config or load_target_config()
    vm = target.windows_vm
    default_target = _default_trace_target(target)
    target_entries = "\n".join(_powershell_trace_target_entry(item) for item in target.trace_targets)
    return f"""param(
  [string]$Target = "{_ps_escape(default_target)}",
  [int]$RunSeconds = 45,
  [string]$TraceRoot = "{_ps_escape(vm.trace_root)}",
  [string]$TestIdPrefix = "windows-vm",
  [switch]$BlockStateTrace,
  [int]$BlockStateMaxRecords = 8192
)
$ErrorActionPreference = "Stop"
$DynamoRoot = Join-Path $TraceRoot "DynamoRIO"
$RuntimeRoot = Join-Path $TraceRoot "{_ps_escape(vm.runtime_dir)}"
$LogRoot = Join-Path $TraceRoot "logs"
$Client = Join-Path $TraceRoot "{_ps_escape(vm.trace_client_name)}"
$Drrun = Get-ChildItem -Path $DynamoRoot -Filter "drrun.exe" -Recurse |
  Where-Object {{ $_.FullName -match "\\\\bin32\\\\drrun\\.exe$" }} |
  Select-Object -First 1
if (-not $Drrun) {{ throw "DynamoRIO bin32\\drrun.exe was not found under $DynamoRoot" }}
if (-not (Test-Path $Client)) {{ throw "{_ps_escape(vm.trace_client_name)} was not found at $Client" }}
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null

$Targets = @{{}}
{target_entries}

function Invoke-WinCRTraceTarget {{
  param([string]$Name, [hashtable]$Spec)
  $Exe = Join-Path $RuntimeRoot $Spec.Executable
  if (-not (Test-Path $Exe)) {{ throw "$($Spec.Executable) was not found at $Exe" }}
  $TestId = "$TestIdPrefix-$Name"
  $Log = Join-Path $LogRoot "$TestId.jsonl"
  Remove-Item -Force -ErrorAction SilentlyContinue $Log, "$Log.*"
  $ClientArgs = @("-c", $Client, "-out", $Log, "-test_id", $TestId)
  if ($BlockStateTrace) {{
    $ClientArgs += @("-block_state_trace", "-block_state_max_records", [string][Math]::Max(1, $BlockStateMaxRecords))
  }}
  $Args = @($ClientArgs + @("--", $Exe))
  foreach ($Arg in $Spec.Args) {{ $Args += $Arg }}
  $WorkingDirectory = if ($Spec.Cwd -and $Spec.Cwd -ne ".") {{ Join-Path $RuntimeRoot $Spec.Cwd }} else {{ $RuntimeRoot }}
  $Process = Start-Process -FilePath $Drrun.FullName -ArgumentList $Args -WorkingDirectory $WorkingDirectory -PassThru
  $TimedOut = $false
  if (-not $Process.WaitForExit($RunSeconds * 1000)) {{
    $TimedOut = $true
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    $Process.WaitForExit() | Out-Null
  }}
  $ExitCode = $Process.ExitCode
  $Parts = Get-ChildItem -Path "$Log.*" -ErrorAction SilentlyContinue | Sort-Object Name
  if ($Parts) {{
    Get-Content -Path $Parts.FullName | Set-Content -Encoding UTF8 $Log
  }}
  [ordered]@{{
    target = $Name
    exe = $Exe
    test_id = $TestId
    log = $Log
    parts = @($Parts | ForEach-Object {{ $_.FullName }})
    timed_out = $TimedOut
    exit_code = $ExitCode
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
  }} | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $LogRoot "$TestId.result.json")
}}

$Selected = if ($Target.ToLowerInvariant() -eq "both") {{ @($Targets.Keys) }} else {{ @($Target.ToLowerInvariant()) }}
foreach ($Name in $Selected) {{
  if (-not $Targets.ContainsKey($Name)) {{
    throw "unknown trace target '$Target'; expected one of: $($Targets.Keys -join ', '), both"
  }}
  Invoke-WinCRTraceTarget -Name $Name -Spec $Targets[$Name]
}}
"""


def qmp_events_from_input_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for record in iter_input_trace(path):
        if record.get("kind") != "event":
            continue
        qmp_event = _input_record_to_qmp(record)
        if qmp_event is not None:
            events.append({"t": float(record.get("t", 0.0)), "qmp": qmp_event})
    return events


def write_qmp_input_events(input_log: Path, out_path: Path) -> dict[str, Any]:
    events = qmp_events_from_input_trace(input_log)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json_dumps(event) + "\n")
    return {"input_log": str(input_log), "out": str(out_path), "events": len(events)}


def replay_qmp_input_events(
    qmp_log: Path,
    *,
    qmp_socket: Path | None = None,
    domain: str | None = None,
    virsh: str = "virsh",
    virsh_uri: str = "qemu:///system",
    speed: float = 1.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    if speed <= 0:
        raise ValueError("speed must be greater than zero")
    if not dry_run and qmp_socket is None and not domain:
        raise ValueError("replay_qmp_input_events requires --socket or --domain unless --dry-run is used")

    events = _read_qmp_event_log(qmp_log)
    result: dict[str, Any] = {
        "qmp_log": str(qmp_log),
        "events": len(events),
        "duration_seconds": max((float(event.get("t", 0.0)) for event in events), default=0.0),
        "speed": speed,
        "dry_run": dry_run,
        "backend": "dry-run" if dry_run else "socket" if qmp_socket is not None else "virsh",
        "domain": domain,
        "socket": str(qmp_socket) if qmp_socket is not None else None,
    }
    if dry_run:
        return result

    sender = _QmpSocketSender(qmp_socket) if qmp_socket is not None else _VirshQmpSender(domain or "", virsh=virsh, uri=virsh_uri)
    sent = 0
    errors: list[str] = []
    previous = 0.0
    with sender:
        for event in events:
            current = float(event.get("t", 0.0))
            delay = max(0.0, (current - previous) / speed)
            if delay:
                time.sleep(delay)
            previous = current
            response = sender.send(event["qmp"])
            sent += 1
            if isinstance(response, dict) and response.get("error"):
                errors.append(json_dumps(response["error"]))
    result["sent"] = sent
    result["errors"] = errors
    result["ok"] = not errors
    return result


def run_windows_guest_trace(
    *,
    host: str,
    user: str,
    out_dir: Path,
    target: str = "Both",
    run_seconds: int = 45,
    test_id_prefix: str = "windows-vm",
    block_state_trace: bool = False,
    block_state_max_records: int = 8192,
    password: str | None = None,
    sshpass: str = "sshpass",
    ssh: str = "ssh",
    scp: str = "scp",
    copy_all_logs: bool = False,
    target_config: TargetConfig | None = None,
) -> dict[str, Any]:
    target_manifest = target_config or load_target_config()
    vm = target_manifest.windows_vm
    out_dir.mkdir(parents=True, exist_ok=True)
    remote = f"{user}@{host}" if user else host
    block_state_args = ""
    if block_state_trace:
        block_state_args = f" -BlockStateTrace -BlockStateMaxRecords {max(1, block_state_max_records)}"
    ps_command = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass "
        f"-File {vm.trace_root}\\{vm.guest_trace_script} -Target {target} "
        f"-RunSeconds {run_seconds} -TestIdPrefix {test_id_prefix}"
        f"{block_state_args}"
    )
    auth_args = []
    if password is not None:
        auth_args = [
            sshpass,
            "-p",
            password,
        ]
        password_options = [
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ]
    else:
        password_options = []
    ssh_command = [*auth_args, ssh, *password_options, remote, ps_command]
    trace_proc = subprocess.run(ssh_command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    scp_commands: list[list[str]] = []
    scp_procs: list[subprocess.CompletedProcess[str]] = []
    remote_trace_root = vm.trace_root.replace("\\", "/")
    if copy_all_logs:
        remote_logs = remote_trace_root + "/logs/."
        scp_commands.append([*auth_args, scp, *password_options, "-r", f"{remote}:{remote_logs}", str(out_dir)])
        scp_procs.append(subprocess.run(scp_commands[-1], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
    else:
        for test_id in _windows_guest_trace_test_ids(target, test_id_prefix, target_manifest):
            result_remote = f"{remote_trace_root}/logs/{test_id}.result.json"
            result_local = out_dir / f"{test_id}.result.json"
            scp_commands.append([*auth_args, scp, *password_options, f"{remote}:{result_remote}", str(out_dir)])
            scp_procs.append(subprocess.run(scp_commands[-1], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            if scp_procs[-1].returncode != 0 or not result_local.exists():
                continue
            guest_result = json.loads(result_local.read_text(encoding="utf-8-sig"))
            for remote_log in _windows_guest_trace_log_paths(guest_result):
                scp_commands.append([*auth_args, scp, *password_options, f"{remote}:{remote_log}", str(out_dir)])
                scp_procs.append(subprocess.run(scp_commands[-1], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
    scp_ok = bool(scp_procs) and all(proc.returncode == 0 for proc in scp_procs)
    return {
        "ok": trace_proc.returncode == 0 and scp_ok,
        "ssh_command": ssh_command,
        "scp_command": scp_commands[-1] if scp_commands else [],
        "scp_commands": scp_commands,
        "trace_returncode": trace_proc.returncode,
        "scp_returncode": 0 if scp_ok else next((proc.returncode for proc in scp_procs if proc.returncode != 0), 1),
        "scp_returncodes": [proc.returncode for proc in scp_procs],
        "stdout": trace_proc.stdout[-4000:],
        "stderr": trace_proc.stderr[-4000:],
        "scp_stdout": "\n".join(proc.stdout for proc in scp_procs)[-4000:],
        "scp_stderr": "\n".join(proc.stderr for proc in scp_procs)[-4000:],
        "out_dir": str(out_dir),
        "copy_all_logs": copy_all_logs,
    }


def check_vfio_host(
    *,
    pci_addresses: Iterable[str],
    required_kernel_params: Iterable[str] = (),
    expected_driver: str = "vfio-pci",
    sysfs_devices_root: Path = Path("/sys/bus/pci/devices"),
    cmdline_path: Path = Path("/proc/cmdline"),
) -> dict[str, Any]:
    cmdline = cmdline_path.read_text(encoding="utf-8", errors="replace") if cmdline_path.exists() else ""
    required_params = list(required_kernel_params)
    missing_kernel_params = [param for param in required_params if param not in cmdline.split()]
    devices = [
        _vfio_device_status(_normalize_pci_address(address), expected_driver, sysfs_devices_root)
        for address in pci_addresses
    ]
    return {
        "ok": not missing_kernel_params and all(device["ok"] for device in devices),
        "expected_driver": expected_driver,
        "required_kernel_params": required_params,
        "missing_kernel_params": missing_kernel_params,
        "cmdline": cmdline.strip(),
        "devices": devices,
    }


def _vfio_device_status(address: str, expected_driver: str, sysfs_devices_root: Path) -> dict[str, Any]:
    device_path = sysfs_devices_root / address
    driver_path = device_path / "driver"
    group_path = device_path / "iommu_group"
    driver = Path(driver_path.resolve()).name if driver_path.exists() else None
    reset_method_path = device_path / "reset_method"
    reset_method = reset_method_path.read_text(encoding="utf-8", errors="replace").strip() if reset_method_path.exists() else None
    group = Path(group_path.resolve()).name if group_path.exists() else None
    return {
        "address": address,
        "path": str(device_path),
        "present": device_path.exists(),
        "driver": driver,
        "driver_ok": driver == expected_driver,
        "iommu_group": group,
        "has_iommu_group": group is not None,
        "has_reset": (device_path / "reset").exists(),
        "reset_method": reset_method,
        "ok": device_path.exists() and driver == expected_driver and group is not None and (device_path / "reset").exists(),
    }


def _normalize_pci_address(address: str) -> str:
    domain_bus, slot_function = address.rsplit(":", 1)
    domain, bus = domain_bus.split(":", 1) if ":" in domain_bus else ("0000", domain_bus)
    slot, function = slot_function.split(".", 1)
    return f"{int(domain, 16):04x}:{int(bus, 16):02x}:{int(slot, 16):02x}.{int(function, 16):x}"


def _windows_guest_trace_test_ids(target: str, test_id_prefix: str, target_config: TargetConfig | None = None) -> list[str]:
    manifest = target_config or load_target_config()
    normalized = target.lower()
    if normalized == "both":
        suffixes = [item.id for item in manifest.trace_targets]
    else:
        trace_target = manifest.trace_target(normalized)
        if trace_target is None:
            raise ValueError(f"unsupported Windows guest trace target: {target}")
        suffixes = [trace_target.id]
    return [f"{test_id_prefix}-{suffix}" for suffix in suffixes]


def _windows_guest_trace_log_paths(guest_result: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for value in [guest_result.get("log"), *guest_result.get("parts", [])]:
        if not value:
            continue
        normalized = str(value).replace("\\", "/")
        if normalized not in paths:
            paths.append(normalized)
    return paths


def render_bundle_readme(config: WindowsVmConfig, out_dir: Path, paths: dict[str, Path]) -> str:
    display_note = _display_mode_readme(config)
    run_commands = _define_run_readme(config, paths)
    vm = config.target_config.windows_vm
    trace_root_posix = vm.trace_root.replace("\\", "/")
    return f"""# {config.target_config.project_name} Windows Trace VM

Generated format: `{WINDOWS_VM_BUNDLE_FORMAT}`

This directory contains generated, private VM control material only. It does
not contain a Windows ISO, target runtime files, licenses, keys, or original assets.

## Build The Staging ISO

Create the private staging ISO:

```sh
{paths["staging_iso_script"]}
```

It contains `Autounattend.xml`, `first-logon.ps1`, `{vm.guest_trace_script}`, the
pinned Windows DynamoRIO tree, `{vm.trace_client_name}`, and `{vm.runtime_stage_dir}/`
copied from the private reference install. The generated `staging-manifest.json` records the
local source paths used for that private media.

## Define And Run

```sh
{run_commands}
```
{display_note}

Use `virsh snapshot-create-as` through the generated snapshot scripts before
first gameplay traces:

```sh
{paths["snapshot_script"]} clean-install
```

## Trace

After `{vm.trace_root}\\guest-ready.json` exists in the guest, run:

```sh
{paths["trace_script"]} <guest-ip-or-name> {config.admin_user}
```

The guest script runs Windows `bin32\\drrun.exe` against the manifest trace
targets, then the host script copies logs from `{trace_root_posix}/logs`.
To run, copy, ingest, regenerate reports, and require mapped coverage for the
selected target PE in one step, use:

```sh
{paths["prove_trace_script"]} <guest-ip-or-name> {config.admin_user} build/catalog/catalog.db build/reports
```

## Deterministic Input

Convert private evdev captures to QMP input commands:

```sh
python -m haloce_catalog emit-qmp-input \\
  --log private/input-traces/client-menu-walk.jsonl \\
  --out private/input-traces/client-menu-walk.qmp.jsonl
```

Send the resulting QMP records through `virsh qemu-monitor-command {config.name}`
with the generated wrapper:

```sh
{paths["qmp_replay_script"]} private/input-traces/client-menu-walk.qmp.jsonl
```

For raw QMP socket debugging, pass `--socket {config.qmp_socket}` to
`python -m haloce_catalog replay-qmp-input`.
"""


def _define_run_readme(config: WindowsVmConfig, paths: dict[str, Path]) -> str:
    commands = [
        str(paths["define_script"]),
        f"virsh start {config.name}",
    ]
    if config.display_mode == "spice-qxl":
        commands.append("remote-viewer spice://127.0.0.1")
    return "\n".join(commands)


def _display_mode_readme(config: WindowsVmConfig) -> str:
    if config.display_mode == "spice-qxl":
        if config.gpu_pci_addresses:
            return """
Display mode: `spice-qxl` with PCI passthrough devices present.

This mode is intended for unattended installation, provisioning, and recovery.
It keeps an emulated QXL/SPICE display available, so Windows may choose QXL
instead of the passthrough GPU for old Direct3D client rendering. For real
3D/gameplay traces, stop the VM and regenerate or define a runtime profile
with the same disk and OVMF vars plus `--display-mode gpu-only`.
"""
        return """
Display mode: `spice-qxl`.

This mode is enough for dedicated-server tracing and guest provisioning. It is
not expected to provide the 3D acceleration needed for real 3D client rendering.
"""
    if config.display_mode == "gpu-only":
        devices = ", ".join(config.gpu_pci_addresses)
        return f"""
Display mode: `gpu-only`.

The XML disables emulated video and relies on PCI passthrough devices:
`{devices}`. Use this mode for client gameplay traces after the guest disk has
been provisioned and the host has booted with those devices bound to
`vfio-pci`. Attach a physical display, dummy plug, or capture path suitable for
the passthrough GPU before starting the VM.
"""
    return ""


def _powershell_trace_target_entry(target: TraceTarget) -> str:
    args = ", ".join(f'"{_ps_escape(arg)}"' for arg in target.args)
    return (
        f'$Targets["{_ps_escape(target.id.lower())}"] = @{{ '
        f'Executable = "{_ps_escape(target.executable)}"; '
        f'Cwd = "{_ps_escape(target.cwd)}"; '
        f'Args = @({args}) '
        "}"
    )


def _ps_escape(value: str) -> str:
    return value.replace("`", "``").replace('"', '`"')


def _powershell_runtime_source_probe(vm: Any) -> str:
    candidates = (vm.runtime_stage_dir, *vm.runtime_stage_aliases)
    quoted = ", ".join(f'"{_ps_escape(candidate)}"' for candidate in candidates if candidate)
    if not quoted:
        quoted = '"TargetRuntime"'
    return f"""  $RuntimeSource = $null
  foreach ($RuntimeCandidate in @({quoted})) {{
    $RuntimeCandidatePath = Join-Path $Drive $RuntimeCandidate
    if (Test-Path $RuntimeCandidatePath) {{
      $RuntimeSource = $RuntimeCandidatePath
      break
    }}
  }}"""


def _staging_manifest(config: WindowsVmConfig, out_dir: Path) -> dict[str, Any]:
    vm = config.target_config.windows_vm
    runtime_root = _runtime_root(config)
    runtime_entries = [
        {"source": _path_or_none(runtime_root), "destination": vm.runtime_stage_dir, "required": True},
        *[
            {"source": _path_or_none(runtime_root), "destination": alias, "required": False}
            for alias in vm.runtime_stage_aliases
        ],
    ]
    return {
        "format": WINDOWS_VM_BUNDLE_FORMAT,
        "generated_at": utc_now(),
        "xorriso": config.xorriso,
        "staging_iso_contents": [
            {"source": str(out_dir / "Autounattend.xml"), "destination": "Autounattend.xml", "required": True},
            {"source": str(out_dir / "first-logon.ps1"), "destination": "first-logon.ps1", "required": True},
            {"source": str(out_dir / vm.guest_trace_script), "destination": vm.guest_trace_script, "required": True},
            {"source": _path_or_none(config.dynamorio_root), "destination": "DynamoRIO", "required": True},
            {"source": _path_or_none(config.trace_client_dll), "destination": vm.trace_client_name, "required": True},
            *runtime_entries,
            {"source": _path_or_none(config.virtio_tools_root), "destination": "VirtioWin", "required": False},
            {"source": _path_or_none(config.spice_tools_root), "destination": "SpiceWin", "required": False},
        ],
    }


def _define_script(domain_xml: Path, libvirt_uri: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
virsh -c {shlex.quote(libvirt_uri)} define {shlex.quote(str(domain_xml))}
"""


def _snapshot_script(name: str, libvirt_uri: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
snapshot="${{1:-pre-trace}}"
virsh -c {shlex.quote(libvirt_uri)} snapshot-create-as --domain {shlex.quote(name)} --name "$snapshot" --disk-only --atomic
"""


def _revert_script(name: str, libvirt_uri: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
snapshot="${{1:?snapshot name required}}"
virsh -c {shlex.quote(libvirt_uri)} snapshot-revert --domain {shlex.quote(name)} --snapshotname "$snapshot" --running
"""


def _host_trace_shell_script(name: str, target_config: TargetConfig) -> str:
    default_target = _default_trace_target(target_config)
    default_user = _default_vm_user(target_config)
    default_password = _default_vm_password(target_config)
    password_expr = _shell_env_default(target_config.windows_vm.password_env, "WINCR_WINDOWS_VM_PASSWORD", default_password)
    block_state_trace_expr = _shell_env_default(
        _block_state_trace_env(target_config), "WINCR_WINDOWS_VM_BLOCK_STATE_TRACE", "1"
    )
    block_state_max_records_expr = _shell_env_default(
        _block_state_max_records_env(target_config), "WINCR_WINDOWS_VM_BLOCK_STATE_MAX_RECORDS", "250000"
    )
    return f"""#!/usr/bin/env bash
set -euo pipefail
guest="${{1:?guest host or IP required}}"
user="${{2:-{default_user}}}"
out_dir="${{3:-private/windows-vm/logs/{name}}}"
target="${{4:-{default_target}}}"
password="{password_expr}"
block_state_trace="{block_state_trace_expr}"
block_state_max_records="{block_state_max_records_expr}"
block_state_args=()
case "$block_state_trace" in
  1|true|TRUE|yes|YES|on|ON) block_state_args=(--block-state-trace --block-state-max-records "$block_state_max_records") ;;
esac
python -m haloce_catalog run-windows-guest-trace --host "$guest" --user "$user" --out-dir "$out_dir" --target "$target" --password "$password" "${{block_state_args[@]}}"
"""


def _shell_env_default(primary_env: str, fallback_env: str, default_value: str) -> str:
    primary = _shell_env_name(primary_env)
    fallback = _shell_env_name(fallback_env)
    default = _shell_escape_default(default_value)
    if primary == fallback:
        return f"${{{primary}:-{default}}}"
    return f"${{{primary}:-${{{fallback}:-{default}}}}}"


def _shell_env_name(name: str) -> str:
    if not name.replace("_", "").isalnum() or not name or name[0].isdigit():
        raise ValueError(f"invalid shell environment variable name: {name!r}")
    return name


def _block_state_trace_env(target_config: TargetConfig) -> str:
    return f"{_windows_vm_env_prefix(target_config)}_BLOCK_STATE_TRACE"


def _block_state_max_records_env(target_config: TargetConfig) -> str:
    return f"{_windows_vm_env_prefix(target_config)}_BLOCK_STATE_MAX_RECORDS"


def _windows_vm_env_prefix(target_config: TargetConfig) -> str:
    password_env = _shell_env_name(target_config.windows_vm.password_env)
    suffix = "_PASSWORD"
    if password_env.endswith(suffix):
        return password_env[: -len(suffix)]
    return password_env


def _shell_escape_default(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


def _host_prove_trace_shell_script(name: str, target_config: TargetConfig) -> str:
    default_target = _default_trace_target(target_config)
    default_user = _default_vm_user(target_config)
    default_password = _default_vm_password(target_config)
    password_expr = _shell_env_default(target_config.windows_vm.password_env, "WINCR_WINDOWS_VM_PASSWORD", default_password)
    skip_reports_expr = _shell_env_default(target_config.windows_vm.skip_reports_env, "WINCR_WINDOWS_VM_SKIP_REPORTS", "0")
    block_state_trace_expr = _shell_env_default(
        _block_state_trace_env(target_config), "WINCR_WINDOWS_VM_BLOCK_STATE_TRACE", "1"
    )
    block_state_max_records_expr = _shell_env_default(
        _block_state_max_records_env(target_config), "WINCR_WINDOWS_VM_BLOCK_STATE_MAX_RECORDS", "250000"
    )
    return f"""#!/usr/bin/env bash
set -euo pipefail
guest="${{1:?guest host or IP required}}"
user="${{2:-{default_user}}}"
db="${{3:-build/catalog/catalog.db}}"
report_dir="${{4:-build/reports/{name}}}"
out_dir="${{5:-private/windows-vm/logs/{name}}}"
target="${{6:-{default_target}}}"
password="{password_expr}"
skip_reports=()
if [[ "{skip_reports_expr}" == "1" ]]; then
  skip_reports=(--skip-reports)
fi
block_state_trace="{block_state_trace_expr}"
block_state_max_records="{block_state_max_records_expr}"
block_state_args=()
case "$block_state_trace" in
  1|true|TRUE|yes|YES|on|ON) block_state_args=(--block-state-trace --block-state-max-records "$block_state_max_records") ;;
esac
python -m haloce_catalog prove-windows-guest-trace --host "$guest" --user "$user" --db "$db" --report-dir "$report_dir" --out-dir "$out_dir" --target "$target" --password "$password" "${{skip_reports[@]}}" "${{block_state_args[@]}}"
"""


def _shell_runtime_stage_alias_copies(vm: Any) -> str:
    lines = []
    for alias in vm.runtime_stage_aliases:
        if alias:
            lines.append(f'  cp -R "$runtime_root" "$stage_dir/{alias}"')
    return "\n".join(lines)


def _runtime_root(config: WindowsVmConfig) -> Path | None:
    return config.runtime_root or config.halo_runtime_root


def _qmp_replay_shell_script(name: str, libvirt_uri: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
log="${{1:?QMP JSONL input log required}}"
speed="${{2:-1.0}}"
python -m haloce_catalog replay-qmp-input --log "$log" --domain {shlex.quote(name)} --virsh-uri {shlex.quote(libvirt_uri)} --speed "$speed"
"""


def _staging_iso_script(config: WindowsVmConfig, out_dir: Path) -> str:
    vm = config.target_config.windows_vm
    dynamorio = "" if config.dynamorio_root is None else str(config.dynamorio_root)
    trace_client = "" if config.trace_client_dll is None else str(config.trace_client_dll)
    runtime_path = _runtime_root(config)
    runtime_root = "" if runtime_path is None else str(runtime_path)
    virtio_tools = "" if config.virtio_tools_root is None else str(config.virtio_tools_root)
    spice_tools = "" if config.spice_tools_root is None else str(config.spice_tools_root)
    xorriso = config.xorriso
    return f"""#!/usr/bin/env bash
set -euo pipefail
default_out_iso={shlex.quote(str(_xml_path(config.autounattend_iso)))}
default_stage_dir={shlex.quote(str(out_dir / "staging-iso"))}
out_iso="${{1:-$default_out_iso}}"
stage_dir="${{2:-$default_stage_dir}}"
if [ -d "$stage_dir" ]; then
  chmod -R u+w "$stage_dir"
fi
rm -rf "$stage_dir"
mkdir -p "$stage_dir"
cp {shlex.quote(str(out_dir / "Autounattend.xml"))} "$stage_dir/Autounattend.xml"
cp {shlex.quote(str(out_dir / "first-logon.ps1"))} "$stage_dir/first-logon.ps1"
cp {shlex.quote(str(out_dir / vm.guest_trace_script))} "$stage_dir/{vm.guest_trace_script}"

dynamorio={shlex.quote(dynamorio)}
trace_client={shlex.quote(trace_client)}
runtime_root={shlex.quote(runtime_root)}
virtio_tools={shlex.quote(virtio_tools)}
spice_tools={shlex.quote(spice_tools)}
xorriso={shlex.quote(xorriso)}
if [ -n "$dynamorio" ]; then
  cp -R "$dynamorio" "$stage_dir/DynamoRIO"
fi
if [ -n "$trace_client" ]; then
  cp "$trace_client" "$stage_dir/{vm.trace_client_name}"
fi
if [ -n "$runtime_root" ]; then
  cp -R "$runtime_root" "$stage_dir/{vm.runtime_stage_dir}"
{_shell_runtime_stage_alias_copies(vm)}
fi
if [ -n "$virtio_tools" ]; then
  cp -R "$virtio_tools" "$stage_dir/VirtioWin"
  if [ -f "$virtio_tools/virtio-win-guest-tools.exe" ]; then
    cp "$virtio_tools/virtio-win-guest-tools.exe" "$stage_dir/virtio-win-guest-tools.exe"
  fi
  driver_dir="$stage_dir/\\$WinPEDriver\\$"
  mkdir -p "$driver_dir"
  for driver_root in "$virtio_tools/amd64/2k25"; do
    [ -d "$driver_root" ] || continue
    cp -R "$driver_root" "$driver_dir/$(basename "$driver_root")"
  done
fi
if [ -n "$spice_tools" ]; then
  cp -R "$spice_tools" "$stage_dir/SpiceWin"
fi

mkdir -p "$(dirname "$out_iso")"
"$xorriso" -as mkisofs -iso-level 3 -J -r -V {shlex.quote(vm.iso_volume_id)} -o "$out_iso" "$stage_dir"
printf '%s\\n' "$out_iso"
"""


def _default_vm_user(target_config: TargetConfig) -> str:
    return target_config.windows_vm.admin_user


def _default_vm_password(target_config: TargetConfig) -> str:
    return target_config.windows_vm.admin_password


def _default_trace_target(target_config: TargetConfig) -> str:
    configured = target_config.windows_vm.default_trace_target
    if configured:
        return configured
    if target_config.trace_targets:
        return target_config.trace_targets[0].id
    return "default"


def _read_qmp_event_log(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if "qmp" not in record:
                raise ValueError(f"{path}:{line_number} lacks qmp command")
            events.append({"t": float(record.get("t", 0.0)), "qmp": record["qmp"]})
    return events


class _VirshQmpSender:
    def __init__(self, domain: str, *, virsh: str, uri: str) -> None:
        self.domain = domain
        self.virsh = virsh
        self.uri = uri

    def __enter__(self) -> "_VirshQmpSender":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def send(self, command: dict[str, Any]) -> dict[str, Any]:
        proc = subprocess.run(
            [self.virsh, "-c", self.uri, "qemu-monitor-command", self.domain, json_dumps(command)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            return {"error": {"class": "virsh", "desc": proc.stderr.strip() or f"virsh exited {proc.returncode}"}}
        stdout = proc.stdout.strip()
        if not stdout:
            return {"return": {}}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"return": stdout}


class _QmpSocketSender:
    def __init__(self, qmp_socket: Path | None) -> None:
        if qmp_socket is None:
            raise ValueError("qmp socket path is required")
        self.qmp_socket = qmp_socket
        self.sock: socket.socket | None = None
        self.reader: Any = None

    def __enter__(self) -> "_QmpSocketSender":
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.connect(str(self.qmp_socket))
        self.reader = self.sock.makefile("r", encoding="utf-8", newline="\n")
        _qmp_read_until_response(self.reader, greeting=True)
        self.send({"execute": "qmp_capabilities"})
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def send(self, command: dict[str, Any]) -> dict[str, Any]:
        if self.sock is None or self.reader is None:
            raise RuntimeError("QMP socket is not connected")
        payload = (json_dumps(command) + "\r\n").encode("utf-8")
        self.sock.sendall(payload)
        return _qmp_read_until_response(self.reader)


def _qmp_read_until_response(reader: Any, *, greeting: bool = False) -> dict[str, Any]:
    while True:
        line = reader.readline()
        if line == "":
            raise RuntimeError("QMP socket closed")
        record = json.loads(line)
        if greeting and "QMP" in record:
            return record
        if not greeting and ("return" in record or "error" in record):
            return record


def _unattend_component(settings: ET.Element, name: str) -> ET.Element:
    return ET.SubElement(
        settings,
        "component",
        {
            "name": name,
            "processorArchitecture": "amd64",
            "publicKeyToken": "31bf3856ad364e35",
            "language": "neutral",
            "versionScope": "nonSxS",
        },
    )


def _create_partition(parent: ET.Element, order: int, partition_type: str, *, size: int | None = None, extend: bool = False) -> None:
    partition = ET.SubElement(parent, "CreatePartition", {f"{{{WCM_NS}}}action": "add"})
    ET.SubElement(partition, "Order").text = str(order)
    ET.SubElement(partition, "Type").text = partition_type
    if size is not None:
        ET.SubElement(partition, "Size").text = str(size)
    if extend:
        ET.SubElement(partition, "Extend").text = "true"


def _modify_partition(
    parent: ET.Element,
    order: int,
    partition_id: int,
    label: str,
    fmt: str,
    *,
    letter: str | None = None,
) -> None:
    partition = ET.SubElement(parent, "ModifyPartition", {f"{{{WCM_NS}}}action": "add"})
    ET.SubElement(partition, "Order").text = str(order)
    ET.SubElement(partition, "PartitionID").text = str(partition_id)
    ET.SubElement(partition, "Label").text = label
    ET.SubElement(partition, "Format").text = fmt
    if letter is not None:
        ET.SubElement(partition, "Letter").text = letter


def _input_record_to_qmp(record: dict[str, Any]) -> dict[str, Any] | None:
    event_type = int(record.get("type", -1))
    code_name = str(record.get("code_name", ""))
    value = int(record.get("value", 0))
    if event_type == 0x01 and code_name.startswith("KEY_"):
        qcode = _QCODE_BY_KEY.get(code_name)
        if qcode is None:
            return None
        return {"execute": "input-send-event", "arguments": {"events": [{"type": "key", "data": {"down": value != 0, "key": {"type": "qcode", "data": qcode}}}]}}
    if event_type == 0x01 and code_name.startswith("BTN_"):
        button = _BUTTON_BY_KEY.get(code_name)
        if button is None:
            return None
        return {"execute": "input-send-event", "arguments": {"events": [{"type": "btn", "data": {"down": value != 0, "button": button}}]}}
    if event_type == 0x02:
        axis = _REL_AXIS_BY_KEY.get(code_name)
        if axis is None:
            return None
        return {"execute": "input-send-event", "arguments": {"events": [{"type": "rel", "data": {"axis": axis, "value": value}}]}}
    return None


_QCODE_BY_KEY = {
    "KEY_ESC": "esc",
    "KEY_ENTER": "ret",
    "KEY_SPACE": "spc",
    "KEY_TAB": "tab",
    "KEY_BACKSPACE": "backspace",
    "KEY_LEFTSHIFT": "shift",
    "KEY_RIGHTSHIFT": "shift_r",
    "KEY_LEFTCTRL": "ctrl",
    "KEY_LEFTALT": "alt",
    "KEY_UP": "up",
    "KEY_DOWN": "down",
    "KEY_LEFT": "left",
    "KEY_RIGHT": "right",
}
for _letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    _QCODE_BY_KEY[f"KEY_{_letter}"] = _letter.lower()
for _number in range(10):
    _QCODE_BY_KEY[f"KEY_{_number}"] = str(_number)
for _function in range(1, 13):
    _QCODE_BY_KEY[f"KEY_F{_function}"] = f"f{_function}"

_BUTTON_BY_KEY = {
    "BTN_LEFT": "left",
    "BTN_RIGHT": "right",
    "BTN_MIDDLE": "middle",
    "BTN_SIDE": "side",
    "BTN_EXTRA": "extra",
}

_REL_AXIS_BY_KEY = {
    "REL_X": "x",
    "REL_Y": "y",
    "REL_WHEEL": "wheel",
    "REL_HWHEEL": "hwheel",
}


def _add_disk(devices: ET.Element, path: Path, dev: str, bus: str, device: str, *, readonly: bool) -> None:
    disk = ET.SubElement(devices, "disk", {"type": "file", "device": device})
    driver_type = "qcow2" if device == "disk" else "raw"
    ET.SubElement(disk, "driver", {"name": "qemu", "type": driver_type, "discard": "unmap"})
    ET.SubElement(disk, "source", {"file": str(_xml_path(path))})
    ET.SubElement(disk, "target", {"dev": dev, "bus": bus})
    if readonly:
        ET.SubElement(disk, "readonly")


def _add_pci_hostdev(devices: ET.Element, address: str) -> None:
    domain, bus, slot, function = _parse_pci_address(address)
    hostdev = ET.SubElement(devices, "hostdev", {"mode": "subsystem", "type": "pci", "managed": "yes"})
    source = ET.SubElement(hostdev, "source")
    ET.SubElement(source, "address", {"domain": domain, "bus": bus, "slot": slot, "function": function})


def _add_usb_hostdev(devices: ET.Element, vendor_product: str) -> None:
    vendor, product = vendor_product.split(":", 1)
    hostdev = ET.SubElement(devices, "hostdev", {"mode": "subsystem", "type": "usb", "managed": "yes"})
    source = ET.SubElement(hostdev, "source")
    ET.SubElement(source, "vendor", {"id": f"0x{vendor.lower().removeprefix('0x')}"})
    ET.SubElement(source, "product", {"id": f"0x{product.lower().removeprefix('0x')}"})


def _parse_pci_address(address: str) -> tuple[str, str, str, str]:
    domain_bus, slot_function = address.rsplit(":", 1)
    domain, bus = domain_bus.split(":", 1) if ":" in domain_bus else ("0000", domain_bus)
    slot, function = slot_function.split(".", 1)
    return (f"0x{domain}", f"0x{bus}", f"0x{slot}", f"0x{function}")


def _path_or_none(path: Path | None) -> str | None:
    return None if path is None else str(path)


def _xml_path(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def _indent(element: ET.Element, level: int = 0) -> None:
    spacer = "\n" + level * "  "
    if len(element):
        if not element.text or not element.text.strip():
            element.text = spacer + "  "
        for child in element:
            _indent(child, level + 1)
        if not element.tail or not element.tail.strip():
            element.tail = spacer
    elif level and (not element.tail or not element.tail.strip()):
        element.tail = spacer
