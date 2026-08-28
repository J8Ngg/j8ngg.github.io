---
title: "Wavlink Router Firmware Analysis Part 1: Extraction and Initial Reconnaissance"
date: 2026-08-28
draft: true
tags:
  - firmware
  - reverse-engineering
  - embedded
  - router-security
  - wavlink
ShowToc: true
TocOpen: true
---

## Introduction

This project explores the firmware of a Wavlink router with the goal of
better understanding embedded Linux systems and the methodology used
during firmware security research.

## Goals

- Obtain the firmware image
- Identify the firmware format
- Extract the filesystem
- Identify the underlying operating system
- Determine the system initialization process
- Identify network-facing services
- Locate interesting binaries
- Begin static analysis

## Firmware Acquisition

...

## Initial Analysis

```bash
file firmware.bin
binwalk firmware.bin
