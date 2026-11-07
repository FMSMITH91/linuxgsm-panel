# Fuzzing

Coverage-guided [Atheris](https://github.com/google/atheris) harnesses for the pure parsers that
consume **untrusted external input**. Each parser must degrade to an empty result on malformed
input, never raise; any uncaught exception is a finding to fix in the parser, not in the harness.
`fuzz_console.py` also asserts that no input leaves an ESC or a bare CR in the rendered output
(the colour renderer may emit an ESC only as the SGR it writes itself).

| Harness | Parses | Untrusted input |
|---|---|---|
| `fuzz_game_status.py` | `_parse_valve_status`, `_parse_idtech3_status`, `_parse_minecraft_list`, `_parse_player_reply` | a game server's `status`/`list` reply |
| `fuzz_firewall.py` | `_parse_ufw_rule`, `_group_ufw_rules`, `_ufw_first_public_rule`, `_r22b_not_limit` | `ufw status numbered` output |
| `fuzz_config.py` | `_parse_cfg`, `_parse_upgradable`, `_parse_mods_available`, `_parse_mods_installed` | LinuxGSM config, `apt list`, mod listings |
| `fuzz_fail2ban.py` | `_tally_f2b_lines`, `_parse_top_ips` | fail2ban log lines and the tallied rows |
| `fuzz_console.py` | `strip_escapes`, `apply_carriage_returns`, `apply_backspaces`, `render_line`, `render`, `render_colour` (`terminal.py`) | game console output, partly player-authored |
| `fuzz_cron.py` | `_split_cron_line`, `_unwrap_cron_command`, `_cron_role`, `_cron_line_managed`, `_cron_log_text`, `_clean_cron_error` | a host's crontab and the cron wrapper's status blob |

## Run locally

```sh
pip install atheris          # plus the panel's own deps: pip install -r requirements.txt
python tests/fuzz/fuzz_game_status.py -max_total_time=60 tests/fuzz/corpus/game_status
```

`corpus/<target>/` holds committed seed inputs. A crash writes a `crash-*` reproducer to the
working directory; re-run the harness with that file as its sole argument to reproduce.

## Adding a target

Add `fuzz_<name>.py` here (pre-import `ssh_manager`'s heavy deps uninstrumented, then
`with atheris.instrument_imports(): from panel.ops import ssh_manager`), a `corpus/<name>/` seed
or two, and `<name>` to `fuzz.yml`'s `matrix.target`.

## CI

- `.github/workflows/fuzz.yml` runs every harness with plain Atheris: 60 s each on pull requests
  that touch a parser or a harness, 600 s each nightly, and on manual dispatch. A crash fails the
  job and uploads the reproducer.
- **ClusterFuzzLite** (`.clusterfuzzlite/`: `Dockerfile`, `build.sh` and `project.yaml`, the
  OSS-Fuzz build contract) runs the same harnesses with the OSS-Fuzz toolchain:

  | workflow | when | what it does |
  |---|---|---|
  | `cflite_pr.yml` | each pull request | fuzzes only the targets the diff reaches, files crashes as SARIF findings, and drops a crash main's build already has |
  | `cflite_batch.yml` | nightly | fuzzes every target and keeps the corpus (`cifuzz-corpus-<target>`) |
  | `cflite_cron.yml` | daily | prunes the corpus and reports coverage (`cifuzz-coverage-latest`) |
  | `cflite_build.yml` | each push to main | keeps that commit's build (`cifuzz-build-address-<commit>`) |

  All of it is stored as Actions artifacts (no storage repository). Every job that reads a
  `cifuzz-*` artifact first checks it was made by a run of this repository's main, because a
  fork's pull request can upload one too; it fails, naming them, while one from anywhere else is stored.
  Delete one with `gh api -X DELETE repos/FMSMITH91/linuxgsm-panel/actions/artifacts/<id>`.

To check the ClusterFuzzLite build locally (needs Docker), from the repo root:

```bash
git clone --depth 1 https://github.com/google/oss-fuzz /tmp/oss-fuzz
python3 /tmp/oss-fuzz/infra/helper.py build_image --external $PWD
python3 /tmp/oss-fuzz/infra/helper.py build_fuzzers --external $PWD
python3 /tmp/oss-fuzz/infra/helper.py check_build --external $PWD --language python
python3 /tmp/oss-fuzz/infra/helper.py run_fuzzer --external $PWD fuzz_console
```

Run `check_build` after touching `build.sh` or a harness's imports: a bundle can compile and still
fail on its first import if a dynamically imported module was not bundled, which is why `build.sh`
collects every submodule of `eventlet`, `paramiko` and `dns` and names `panel.core.config` as a
hidden import.
