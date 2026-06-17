"""Vendored prompt templates per workload.

The bench's drivers don't depend on Agent-S's PROCEDURAL_MEMORY
file directly — workloads import their templates from here. Edit a
file in this directory to change a workload's prompts; the
``Workload.prompt_overrides`` map is populated from the strings
defined here.

Injection of these overrides into the running Agent-S submodule still
requires the submodule's cli_app.py to grow a ``--prompt_overrides``
flag (see CLAUDE.md "Agent-S prompt + agent-internal knobs"). Until
then, these vendored copies are read-only inspectable.
"""

from .agent_s_default import AGENT_S_DEFAULT_PROMPTS
