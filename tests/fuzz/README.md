# Fuzzing

Coverage-guided [Atheris](https://github.com/google/atheris) harnesses for the pure parsers that
consume **untrusted external input**. Each parser is best-effort: it must degrade to an empty result
on malformed input, never raise. The harnesses assert exactly that — any uncaught exception is a
finding to fix in the parser (not to suppress in the harness).

`fuzz_console.py` additionally asserts an OUTPUT property, because `terminal.py` exists to produce
one: no input may leave an ESC or a bare CR in the rendered result, since those are exactly the
bytes it strips before the text reaches a browser.

| Harness | Parses | Source of untrusted input |
|---|---|---|
| `fuzz_game_status.py` | `_parse_valve_status`, `_parse_idtech3_status`, `_parse_minecraft_list` | a remote game server's `status`/`list` reply |
| `fuzz_firewall.py` | `_parse_ufw_rule`, `_group_ufw_rules` | `ufw status numbered` output |
| `fuzz_config.py` | `_parse_cfg`, `_parse_upgradable`, `_parse_mods_available`, `_parse_mods_installed` | LinuxGSM config / `apt list` / mod listings |
| `fuzz_fail2ban.py` | `_parse_top_ips` | the fail2ban log counting pipeline |
| `fuzz_console.py` | `strip_escapes`, `apply_carriage_returns`, `apply_backspaces`, `render` (`terminal.py`) | a game console's output — player names, chat and RCON replies, so partly attacker-*authored* |
| `fuzz_cron.py` | `_split_cron_line`, `_unwrap_cron_command`, `_cron_role`, `_cron_line_managed`, `_cron_log_text`, `_clean_cron_error` | a remote host's crontab, and the base64 status blob the panel's cron wrapper writes |

## Run locally

```sh
pip install atheris          # plus the panel's own deps: pip install -r requirements.txt
python tests/fuzz/fuzz_game_status.py -max_total_time=60 tests/fuzz/corpus/game_status
```

`corpus/<target>/` holds committed seed inputs (valid examples the fuzzer mutates from). A crash
writes a `crash-*` reproducer to the working directory; re-run the harness with that file as the
sole argument to reproduce.

## CI

`.github/workflows/fuzz.yml` runs every harness in parallel on pushes/PRs that touch a parser or a
harness (60s each) and nightly (600s each). A crash fails the job and uploads the reproducer as an
artifact.

## Adding a target

Add `fuzz_<name>.py` here (pre-import `ssh_manager`'s heavy deps uninstrumented, then
`with atheris.instrument_imports(): import ssh_manager`), a `corpus/<name>/` seed or two, and
`<name>` to the workflow's `matrix.target`.
