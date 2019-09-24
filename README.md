# Emergency Alert Script

> This script is my production of learning [Gscan](https://github.com/grayddq/GScan). GScan is a great tool to both learn and  do emergency check.

## Author

ChriskaliX

## Usage

python3 main.py

(ONLY python>3.6 supported)

## Check list

> Backdoor

|Checklist|
|-|
|LD_PRELOAD|
|LD_AOUT_PRELOAD|
|LD_ELF_PRELOAD|
|LD_LIBRARY_PATH|
|PROMPT_COMMAND|
|Ld_so_preload|
|Cron_check|
|SSH Process|
|SSH_wrapper|
|Inted|
|Xinetd|
|Setuid|
|Chmod_777|
|Startup_check|
|Alias|

> Configuration

|Checklist|
|-|
|Dns check|
|Iptables check|
|Host check|

> History Check

|Checklist|
|-|
|History check|

> Log Check

|Checklist|
|-|
|wtmp|
|utmp|
|lastlog|
|authlog|

> Process Check

|Checklist|
|-|
|cpu_mem_check|
|shell_check|
|exe_check|

> User Check

|Checklist|
|-|
|root check|
|empty check|
|sudo check|
|authorized_check|
|permission_check|

## Purpose

- learn something of emergency alert
- practice my python(STILL shit though)
- learn more about Linux

## Difference

- Pure python，No Linux command used
- some differences between file check
- delete some plugins

## PLAN

- rebuild the framework(It's really silly...)
- support ALL linux(Now only centos)
