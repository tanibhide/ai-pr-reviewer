## Security review (AI triage)

The scanners reported **11** findings. After triage: **6 to fix**, 2 likely false alarms, 3 duplicates.

### Issues to fix
| Severity | Location | Issue | Suggested fix |
|---|---|---|---|
| HIGH | `app/admin.py:26` | The code uses shell=True for a subprocess call, which allows for command injection and potential security vulnerabilities. | Disable the use of shell=True for subprocess calls and use alternative methods for network communication. |
| HIGH | `app/admin.py:41` | MD5 is a known weak cryptographic hash function, making it unsuitable for password hashing. | Replace the MD5 hash function with a stronger algorithm like bcrypt or scrypt. |
| MEDIUM | `app/admin.py:20` | The code directly inserts user input into the SQL query, creating a potential SQL injection vulnerability. | Use parameterized queries to prevent user input from being directly inserted into the SQL query. |
| MEDIUM | `app/admin.py:31` | The code directly deserializes untrusted data using `pickle.loads`, which is a known security vulnerability. | Use a safer deserialization method like `json.loads` or `ast.literal_eval` instead of `pickle.loads` to deserialize untrusted data. |
| MEDIUM | `app/admin.py:36` | The code uses `eval` to execute user-provided expressions, which is a known security vulnerability. | Replace `eval` with a safer alternative like `ast.literal_eval` for handling user-provided data. |
| LOW | `app/admin.py:14` | The code directly hardcodes the password, which is a clear security risk. | Use a secure method like environment variables or a configuration file to store the password. |

### Dismissed as false alarms
- `app/admin.py:9` (B403 blacklist) — The code snippet does not explicitly use the pickle module for any sensitive operations, and the mention of a security vulnerability is not directly related to…
- `app/admin.py:11` (B404 blacklist) — The code imports the subprocess module, which is a common practice for interacting with external processes. The message is not specific to a security vulnerabi…

_Triage by a local LLM. Treat as a first pass, not the final word._
