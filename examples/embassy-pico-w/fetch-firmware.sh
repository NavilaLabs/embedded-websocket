#!/usr/bin/env bash
# Downloads the firmware of the CYW43439 WiFi chip from the embassy repository, at the commit of
# the cyw43 release this example uses. The firmware is under the permissive binary license in
# firmware/LICENSE-permissive-binary-license-1.0.txt.
set -euo pipefail
cd "$(dirname "$0")"
commit=84444a19eb57d978e3c09fcdc8e60cdd7278eb03
mkdir -p firmware
for file in 43439A0.bin 43439A0_clm.bin nvram_rp2040.bin LICENSE-permissive-binary-license-1.0.txt; do
    curl --fail --silent --show-error --location --output "firmware/$file" \
        "https://raw.githubusercontent.com/embassy-rs/embassy/$commit/cyw43-firmware/$file"
done
(cd firmware && sha256sum --check --quiet) <<SUMS
5555e0261da2610a500d68c18d895cace0152bbefbf76f4aa683ebce77e3d7eb  43439A0.bin
e712b3d218e8b1e2747b092e03b8b0afcb8c8c8e355d2a4a0d47b493800f3f89  43439A0_clm.bin
4904bdbb0c937bd0ac2eb2a1d62f2da4dd90e32082384e02874e8d671b0f330d  nvram_rp2040.bin
5f65b8a496ac27afda41917c18cb6e690b4a022df1f5a12ea823eb38a287f50e  LICENSE-permissive-binary-license-1.0.txt
SUMS
