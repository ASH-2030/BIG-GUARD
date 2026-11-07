# Dataset schema

## Required columns
| Column | Description |
|---|---|
| `event_id` | Unique id (generated if blank; duplicates dropped) |
| `timestamp` | ISO-8601 or parseable datetime; interpreted as UTC. Rows with invalid timestamps are dropped and reported |
| `identity` | Account/identity name (required) |
| `device` | Device/host |
| `source_ip` | Source IP (synthetic data uses RFC 5737 ranges only) |
| `event_type` | `login_success`, `login_failure`, `process_exec`, `resource_access` (required; other values kept) |
| `process` | Process name or `none` |
| `resource` | Resource name or `none` |
| `session_id` | Session identifier |
| `auth_status` | `success`, `failure`, `not_applicable` (aliases such as `failed`, `n/a` are normalised) |
| `event_context` | Free-text context label (e.g. `routine_work`, `remote_logon`, `admin_change_window`) |

## Optional columns
`is_synthetic` (bool), `label` (0/1 ground truth, enables evaluation), `scenario` (generator scenario name; never a model input).

## Missing values
`process`/`resource` → `none`; `device`, `source_ip`, `session_id`, `event_context` → `unknown`. Missing timestamp/identity/event_type → row dropped. Limit: 100,000 rows.

## Synthetic scenarios (seed 42: 19,445 events, 54 identities, 90 days, 151 positive events)
Normal, benign hard negatives (`benign_admin_maintenance`, `benign_new_device`, `benign_leave_return`, `benign_failed_logins`) and
suspicious scenarios (`dormant_misuse`, `lotl_context`, `unusual_login`, `multi_device_access`, `unusual_access_sweep`).
Note: inside `lotl_context` and `unusual_access_sweep` the ordinary login event is labelled 0.
