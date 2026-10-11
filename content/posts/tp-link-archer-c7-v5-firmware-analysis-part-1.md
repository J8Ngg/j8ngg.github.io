---
title: "TP-Link Archer C7 v5 Firmware Analysis Part 1: Reconnaissance and Firmware Acquisition"
date: 2026-10-10
draft: false
tags:
  - firmware
  - reverse-engineering
  - embedded
  - router-security
  - tp-link
---

## Introduction

This project documents my analysis of the TP-Link Archer C7 v5 router firmware. My goal is to work through the firmware research process from initial target reconnaissance and firmware acquisition to filesystem analysis, service enumeration, and eventually reverse engineering interesting binaries.

This first part focuses on understanding the target, obtaining the manufacturer's stock firmware, recording the exact sample I selected, and performing some initial binary triage before extracting anything.

## Why the Archer C7 v5?

I first came across the TP-Link Archer C7 v5 through [DD-WRT's router database](https://dd-wrt.com/support/router-database/). I chose it because TP-Link still provides the stock firmware, and there is enough public documentation on the hardware for me to understand the platform as I work through it.

Since this is my first full firmware analysis project, I wanted a target where I could focus on learning the process from start to finish. The Archer C7 v5 also gives me vendor-specific firmware and services to look into later, which should give me room to move from basic firmware extraction into service analysis and reverse engineering.

![DD-WRT router database result for the Archer C7 5.x](/images/archer-c7-v5/dd-wrt_archer_search.png)

I used the DD-WRT database to identify the Archer C7 v5 as a possible research target. I then researched the hardware separately and obtained the stock firmware directly from TP-Link. For this project, the database was a starting point rather than the source of the firmware or the final authority on the router's specifications.

## Why is it suitable for this project?

It is suitable because it allows me to work through the vulnerability research methodology and take the necessary steps before dissecting the firmware and forming hypotheses about what may be happening beneath what it tells us at face value. It is really about doing due diligence on what I will be working with.

## Basic device reconnaissance

After selecting the Archer C7 v5, I searched for more detailed hardware information and found [OpenWrt's device documentation](https://openwrt.org/toh/hwdata/tp-link/tp-link_archer_c7_v5).

OpenWrt reports the following specifications for the Archer C7 v5. I have not independently confirmed all of these details as part of this project.

- Manufacturer: TP-Link
- Model: Archer C7
- Hardware revision: v5
- Device type: Wireless router
- Architecture: MIPS 24Kc (OpenWrt package architecture: `mips_24kc`)
- SoC: Qualcomm Atheros QCA9563
- RAM: 128 MB
- Flash: 16 MB
- Bootloader: U-Boot

## Firmware acquisition

I went to [TP-Link's official support page for the Archer C7 v5](https://www.tp-link.com/us/support/download/archer-c7/v5/) to obtain the manufacturer's stock firmware.

- Model and region: Archer C7 (US) v5
- Firmware version: 1.2.1
- Build: 20220715
- Published date: November 8, 2022
- Original archive: `Archer C7(US)_V5.0_220715.zip`
- Firmware image: `c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin`

![TP-Link firmware selection for the Archer C7 v5](/images/archer-c7-v5/tp-link_firmware_selection.png)

## Integrity checks

I calculated SHA-256 and MD5 hashes of the extracted firmware image and recorded its filesystem metadata.

```bash
sha256sum 'c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin'

14bab8d9cfe2062205ec6a3975d83b8dc1f770688008b8024a8bf214bfc7fcaa  c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin
```

```bash
md5sum 'c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin'

f35b2fbf9568ef2df9108b3df66a6d5f  c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin
```

```bash
stat 'c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin'

File: c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin
Size: 15727744        Blocks: 30720      IO Block: 4096   regular file
Modify: 2022-09-01 18:34:44.000000000 -0700
```

I recorded both hashes so I can identify the exact firmware sample used throughout the project. SHA-256 is my primary fingerprint, while MD5 provides an additional identifier that may be useful when comparing the sample with other research. Recalculating these hashes later would reveal whether my local file has changed, but they do not prove that TP-Link cryptographically signed or authenticated it.

The modification timestamp came from the extracted package. It is filesystem metadata and should not be confused with the firmware build date or TP-Link's publication date.

## Initial triage

### File identification

I started with `file` to see whether its signature database recognized the firmware container.

```bash
file 'c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin'

c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin: data
```

The `file` utility did not recognize the firmware's outer format and identified it only as `data`. This does not mean the image is empty, encrypted, or unstructured. It only means that the format was not recognized by the signatures available to `file`.

### Header inspection

I then used `xxd` to inspect the first 256 bytes without modifying the image.

```bash
xxd -g 1 -l 256 'c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin'

00000000: 00 ef fc 80 6b 8b 7f 1b 3e ae f6 6e a2 ab fa d9  ....k...>..n....
00000010: db a8 e9 f6 66 77 2d 74 79 70 65 3a 43 6c 6f 75  ....fw-type:Clou
00000020: 64 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00  d...............
00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

The first four bytes shown by `xxd` are `00 ef fc 80`. Interpreted as a big-endian integer, this is `0x00effc80`, or 15,727,744 bytes, which exactly matches the file size reported by `stat`.

The following 16 bytes are in the part of the SafeLoader preamble that OpenWrt identifies as an internal MD5 checksum. This field is part of the firmware container and is separate from the whole-file MD5 hash I calculated earlier.

The header also contains the string `fw-type:Cloud` at offset `0x14`. This matches the SafeLoader Cloud layout described by [OpenWrt's `tplink-safeloader` implementation](https://github.com/openwrt/firmware-utils/blob/master/src/tplink-safeloader.c), which uses a 20-byte preamble, a header, and a payload beginning at offset `0x1014`.

### Readable strings

Finally, I used `strings` to look for readable sequences that might reveal version information, component names, or a partition layout. The `-a` option scans the entire file, `-n 8` requires a minimum string length of eight characters, and `-t x` prints each string's file offset in hexadecimal.

```bash
strings -a -n 8 -t x 'c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin' | head -n 50

14 fw-type:Cloud
18d 9G3&H s^
1014 fwup-ptn fs-uboot base 0x01000 size 0x0dbbf
1042 fwup-ptn partition-table base 0x00800 size 0x00800
1077 fwup-ptn soft-version base 0x0ebbf size 0x00059
10a9 fwup-ptn extra-para base 0x0ec18 size 0x0000b
10d9 fwup-ptn support-list base 0x0ec23 size 0x001cf
110b fwup-ptn profile base 0x0edf2 size 0x035bb
1138 fwup-ptn os-image base 0x123ad size 0x109d11
1167 fwup-ptn file-system base 0x11c0be size 0xddf96d
119a fwup-ptn default-config base 0xefba2b size 0x03241
1818 partition factory-boot base 0x00000 size 0x20000
1849 partition fs-uboot base 0x20000 size 0x20000
1876 partition partition-table base 0x40000 size 0x10000
18aa partition radio base 0x50000 size 0x10000
18d4 partition default-mac base 0x60000 size 0x00200
1904 partition pin base 0x60200 size 0x00200
192c partition device-id base 0x60400 size 0x00100
195a partition product-info base 0x60500 size 0x0fb00
198b partition soft-version base 0x70000 size 0x01000
19bc partition extra-para base 0x71000 size 0x01000
19eb partition support-list base 0x72000 size 0x0a000
1a1c partition profile base 0x7c000 size 0x04000
1a48 partition user-config base 0x80000 size 0x40000
1a78 partition os-image base 0xc0000 size 0x120000
1aa6 partition file-system base 0x1e0000 size 0xde0000
1ad8 partition log base 0xfc0000 size 0x20000
1b01 partition certificate base 0xfe0000 size 0x10000
1b32 partition default-config base 0xff0000 size 0x10000
5574 U-Boot 1.1.4-gd4bfd123-dirty (Jul 14 2022 - 23:57:56)
59cc ap152 - Dragonfly 1.
5ae0 u-boot image
626b AB>WGuqQ
6371 27lb>6">&2
695b @SC9    "3H
a46f YXk6PyEH
c587 wK]qcx9O
c8c4 pz9V:bQG
ccd0 ~kHwsy1\
f269 ~$KV'13r
fbdb soft_ver:1.2.1 Build 20220715 rel.19099
fc03 fw_id:731826CF2CED0FB92DB9F88FB18ADF12
fc3f SupportList:
fc4c {product_name:Archer C7,product_ver:5.0.0,special_id:45550000}
fc8b {product_name:Archer C7,product_ver:5.0.0,special_id:55530000}
fcca {product_name:Archer C7,product_ver:5.0.0,special_id:43410000}
fd09 {product_name:Archer C7,product_ver:5.0.0,special_id:4A500000}
fd48 {product_name:Archer C7,product_ver:5.0.0,special_id:54570000}
fd87 {product_name:Archer C7,product_ver:5.0.0,special_id:52550000}
fdc6 {product_name:Archer C7,product_ver:5.0.0,special_id:4B520000}
```

The initial strings reveal two different sets of partition information. Entries beginning with `fwup-ptn` appear to describe components contained in the firmware update package. The later `partition` entries appear to describe the router's intended flash layout. These two sets of values should not automatically be treated as offsets into the same address space.

The final flash partition ends at address `0x1000000`, which corresponds to 16 MiB. This is consistent with the 16 MB flash capacity reported by OpenWrt.

The output also contains an entry for an `fs-uboot` component and a string identifying U-Boot 1.1.4. This supports OpenWrt's report that the device uses U-Boot. The version metadata and support list also identify firmware version 1.2.1 and Archer C7 hardware version 5.0.0, which corroborates that I selected firmware intended for my research target.

Some results appear to be incidental printable byte sequences rather than meaningful text, which is expected when running `strings` across an entire binary image.

## What I know so far

The initial triage gave me several useful reference points without requiring me to extract or modify the firmware:

- The firmware image is 15,727,744 bytes, and that size is encoded in its first four bytes.
- The outer container appears consistent with TP-Link's SafeLoader Cloud format.
- The embedded metadata identifies firmware version 1.2.1 and Archer C7 hardware version 5.0.0.
- The strings expose both update-package components and an intended 16 MiB flash layout.
- A U-Boot version string supports the bootloader information reported by OpenWrt.

These observations do not establish that the firmware is vulnerable, and they do not yet confirm the filesystem format or executable architecture. They give me a documented baseline for the next phase of the project.

## Next steps

In Part 2, I will examine the firmware structure with Binwalk, identify and extract the embedded filesystem, and inspect its contents. I also want to confirm the architecture from an extracted executable rather than relying only on external documentation.
