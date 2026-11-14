#!/usr/bin/env python3
"""Measures the flash and RAM the library needs on a Cortex-M4F and reports it as Markdown.

    size/report.py measure > current.json
    size/report.py markdown current.json [baseline.json]

`measure` builds the probes in this directory with the toolchain in TOOLCHAIN (default: the one
rustup selects) and needs its llvm-tools component. `markdown` prints tables, with the change
against `baseline.json` when it is given.
"""

import json
import os
import pathlib
import subprocess
import sys

TARGET = "thumbv7em-none-eabihf"
PROBES = ["codec", "blocking", "asynch"]
DIRECTORY = pathlib.Path(__file__).resolve().parent


def cargo(*arguments):
    toolchain = os.environ.get("TOOLCHAIN")
    command = ["cargo"] + ([f"+{toolchain}"] if toolchain else []) + list(arguments)
    subprocess.run(command, cwd=DIRECTORY, check=True)


def llvm_tool(name):
    toolchain = os.environ.get("TOOLCHAIN")
    rustc = ["rustc"] + ([f"+{toolchain}"] if toolchain else [])
    sysroot = subprocess.run(rustc + ["--print", "sysroot"], capture_output=True, text=True, check=True)
    host = subprocess.run(rustc + ["--print", "host-tuple"], capture_output=True, text=True, check=True)
    return pathlib.Path(sysroot.stdout.strip()) / "lib/rustlib" / host.stdout.strip() / "bin" / name


def binary(name):
    return DIRECTORY / "target" / TARGET / "release" / name


def sections(name):
    """Returns text, data and bss of a probe in the Berkeley format of llvm-size."""
    output = subprocess.run(
        [llvm_tool("llvm-size"), binary(name)], capture_output=True, text=True, check=True
    ).stdout
    text, data, bss = output.splitlines()[1].split()[:3]
    return int(text), int(data), int(bss)


def type_sizes():
    output = subprocess.run(
        [llvm_tool("llvm-nm"), "--print-size", binary("type_sizes")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    sizes = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[3].startswith("SIZE_OF_"):
            sizes[fields[3][len("SIZE_OF_"):].lower()] = int(fields[1], 16)
    return dict(sorted(sizes.items()))


def measure():
    cargo("build", "--release", "--quiet")
    empty_text, empty_data, empty_bss = sections("empty")
    probes = {}
    for probe in PROBES:
        text, data, bss = sections(probe)
        probes[probe] = {
            "flash": text + data - empty_text - empty_data,
            "ram": data + bss - empty_data - empty_bss,
        }
    json.dump({"probes": probes, "types": type_sizes()}, sys.stdout, indent=2)
    print()


def cell(value, baseline):
    if baseline is None:
        return f"{value}"
    change = value - baseline
    return f"{value} ({change:+})" if change else f"{value}"


def markdown(current_path, baseline_path=None):
    current = json.loads(pathlib.Path(current_path).read_text())
    baseline = json.loads(pathlib.Path(baseline_path).read_text()) if baseline_path else None
    against = " (change against master)" if baseline else ""

    print(f"### Flash and RAM on {TARGET}{against}\n")
    print("Bytes the library adds to an empty firmware, built with `opt-level = \"s\"` and LTO. ")
    print("RAM counts static data only; buffers and futures are on the stack of the caller.\n")
    print("| Probe | Flash | Static RAM |")
    print("|---|---:|---:|")
    for probe, sizes in current["probes"].items():
        old = baseline["probes"].get(probe) if baseline else None
        flash = cell(sizes["flash"], old and old["flash"])
        ram = cell(sizes["ram"], old and old["ram"])
        print(f"| {probe} | {flash} | {ram} |")

    print(f"\n### Type sizes on {TARGET}{against}\n")
    print("| Type | Bytes |")
    print("|---|---:|")
    for name, size in current["types"].items():
        old = baseline["types"].get(name) if baseline else None
        print(f"| {name} | {cell(size, old)} |")


def main():
    if sys.argv[1:2] == ["measure"]:
        measure()
    elif sys.argv[1:2] == ["markdown"] and 3 <= len(sys.argv) <= 4:
        markdown(*sys.argv[2:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
