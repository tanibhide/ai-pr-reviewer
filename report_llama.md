## Security review (AI triage)

The scanners reported **22** findings. After triage: **2 to fix**, 11 likely false alarms, 5 duplicates.

> **Note:** 4 finding(s) could not be triaged automatically.

### Issues to fix
| Severity | Location | Issue | Suggested fix |
|---|---|---|---|
| HIGH | `app/admin.py:41` | The MD5 hash function is indeed considered insecure for password storage due to its predictable nature and lack of collision resistance. | Use a stronger hash function like bcrypt or Argon2 for password storage. |
| MEDIUM | `app/admin.py:31` | The use of `pickle.loads()` to deserialize untrusted data without proper validation or sanitization can lead to arbitrary code execution. | Use `pickle.loads()` with the `safe` parameter set to `True` to restrict the types of objects that can be loaded, e.g. `return pickle.loads(data, encoding='utf… |

### Dismissed as false alarms
- `app/admin.py:26` (B602 subprocess_popen_with_shell_equals_true) — The use of shell=True with a valid command (ping) is not a security issue, as it is a common and safe way to execute system commands.
- `app/auth.py:23` (jwt-python-hardcoded-secret) — The secret is hardcoded in the code, but it is also hardcoded in the `jwt.decode` function, suggesting that the secret is not actually being used in a way that…
- `app/auth.py:35` (B501 request_with_no_cert_validation) — The verify=False parameter is used to disable SSL certificate checks, but it is not being used to disable SSL certificate validation, which is the actual secur…
- `app/upload.py:26` (B202 tarfile_unsafe_members) — The tarfile.extractall function is used with a valid destination path, indicating that the extraction process is intended to occur.
- `app/admin.py:36` (B307 blacklist) — eval is being used to execute a string that is supposed to be a valid Python expression, not arbitrary user input.
- `app/auth.py:43` (B108 hardcoded_tmp_directory) — The HOME environment variable is not set, but /tmp is used instead, which is a common and safe default directory.
- `app/upload.py:21` (B506 yaml_load) — uses yaml.load() which is deprecated in favor of yaml.safe_load() but still supported for backwards compatibility
- `app/upload.py:30` (B108 hardcoded_tmp_directory) — The use of '/tmp/' is a common and secure convention for temporary directories in Unix-like systems.
- `app/admin.py:9` (B403 blacklist) — The code is commented out and marked as 'Never use this code in a real application', indicating it is not being used.
- `app/admin.py:11` (B404 blacklist) — The import of the subprocess module is a common and necessary import for many Python applications, and without further context, it is unlikely to pose a securi…
- `app/admin.py:14` (B105 hardcoded_password_string) — The password is hardcoded for a specific purpose (admin access) and is not a sensitive value that should be stored in plaintext

_Triage by a local LLM. Treat as a first pass, not the final word._
