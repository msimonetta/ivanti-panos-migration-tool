# Ivanti to PAN-OS Translator

`IvantiToPanosTranslator.ps1` converts Ivanti VPN tunneling resource policies (`<network-connect-acl>`) into Palo Alto Panorama PAN-OS `set` commands.

## Requirements

- PowerShell

## Usage

```bash
pwsh -File IvantiToPanosTranslator.ps1 \
  -InputFile <ivanti_input_file> \
  -OutputFile <panos_output_file> \
  -DeviceGroup <panorama_device_group> \
  -Rulebase <pre|post> \
  [-SecurityProfileGroup <profile_group>] \
  [-LogForwardingProfile <log_forwarding_profile>] \
  [-FromZone <from_zone>] \
  [-ToZone <to_zone>] \
  [-LogFile <log_file_path>]
```

### Parameters

- `-InputFile` (required): Ivanti source file with `<network-connect-acl>` blocks.
- `-OutputFile` (required): Output file with generated PAN-OS `set` commands.
- `-DeviceGroup` (required): Panorama device group name.
- `-Rulebase` (required): `pre` or `post`.
- `-SecurityProfileGroup` (optional): PAN-OS profile group applied to rules.
- `-LogForwardingProfile` (optional): PAN-OS log forwarding profile applied to rules.
- `-FromZone` (optional): Source zone for generated rules. Defaults to `trust`.
- `-ToZone` (optional): Destination zone for generated rules. Defaults to `trust`.
- `-LogFile` (optional): Transcript log path. Defaults to `migration.log`.

## Example

```bash
pwsh -File IvantiToPanosTranslator.ps1 \
  -InputFile sample-input.txt \
  -OutputFile panos_commands.txt \
  -DeviceGroup MyFirewallDG \
  -Rulebase pre \
  -SecurityProfileGroup default-spg \
  -LogForwardingProfile default_log_fwd \
  -FromZone trust \
  -ToZone trust
```

## Translation Rules (Current Behavior)

- `deny` is translated to PAN-OS `drop`.
- `allow` remains `allow`.
- If action is `rules`, nested `<rule>` resources are used.
- If action is `rules` but nested rules are missing, top-level ACL resources are used.
- Resource defaults:
  - Missing protocol -> both TCP and UDP.
  - Missing/wildcard address -> destination `any`.
  - Missing mask -> `/32`.
  - Address object naming:
    - `/32` -> `HO_<ip>`
    - non-`/32` -> `NET_<ip>-<mask>` (example: `NET_192.168.0.0-24`)
  - Missing/wildcard port with explicit `tcp://` or `udp://` -> protocol-scoped service object `tcp-any`/`udp-any` (port `0-65535`).
  - Missing/wildcard port with omitted protocol -> service `any`.
- ICMP resources are translated to dedicated ICMP policy groups using:
  - `application ping`
  - `service application-default`
- Resources containing `1.1.1.1` are ignored.
- Dynamic placeholders that do not match parser format are ignored with warnings.
- Every generated security rule includes `from` and `to` zones.
  - Defaults: `from trust`, `to trust`
  - Override with `-FromZone` and `-ToZone`

## Rule Grouping Strategy

To avoid over-permissive destination/service cross-products while lowering rule count:

- Rules are grouped destination-first.
- For each destination, all non-ICMP services are merged into one rule.
- If the same destination includes ICMP and non-ICMP resources, ICMP is split into its own rule (App-ID `ping` + `application-default` service).
- Wildcard service (`any`) remains constrained to destinations that explicitly resolve to wildcard service behavior.

## Generated Artifacts

- PAN-OS commands file (from `-OutputFile`).
- Transcript log file (`migration.log` by default, or `-LogFile`).
