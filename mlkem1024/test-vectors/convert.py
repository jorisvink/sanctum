#
# Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import json
import struct

def dump_keygen(path, hdr):
    with open(path, "r") as f:
        tests = json.loads(f.read())

    f = open(hdr, "wb")

    for tg in tests["testGroups"]:
        if tg["parameterSet"] != "ML-KEM-1024":
            continue

        for tc in tg["tests"]:
            f.write(struct.pack("<I", tc["tcId"]))

            z = bytes.fromhex(tc["z"])
            d = bytes.fromhex(tc["d"])
            ek = bytes.fromhex(tc["ek"])
            dk = bytes.fromhex(tc["dk"])

            f.write(struct.pack("32s", z))
            f.write(struct.pack("32s", d))
            f.write(struct.pack("1568s", ek))
            f.write(struct.pack("3168s", dk))

        f.flush()

    f.close()

def dump_encap_decap(path, hdr):
    with open(path, "r") as f:
        tests = json.loads(f.read())

    f = open(hdr, "wb")

    for tg in tests["testGroups"]:
        if tg["parameterSet"] != "ML-KEM-1024" or tg["testType"] != "AFT":
            continue

        for tc in tg["tests"]:
            f.write(struct.pack("<I", tc["tcId"]))

            print(f"{tc}")

            c = bytes.fromhex(tc["c"])
            k = bytes.fromhex(tc["k"])
            m = bytes.fromhex(tc["m"])
            ek = bytes.fromhex(tc["ek"])
            dk = bytes.fromhex(tc["dk"])

            f.write(struct.pack("1568s", ek))
            f.write(struct.pack("3168s", dk))
            f.write(struct.pack("1568s", c))
            f.write(struct.pack("32s", k))
            f.write(struct.pack("32s", m))

        f.flush()

    f.close()

dump_keygen(
    "acvp_nist_keygen_fips203.json",
    "acvp_nist_keygen_fips203.bin"
)

dump_encap_decap(
    "acvp_nist_encap_decap_fips203.json",
    "acvp_nist_encap_decap_fips203.bin"
)
