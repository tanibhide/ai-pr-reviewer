## Security review (AI triage)

The scanners reported **22** findings. After triage: **10 to fix**, 7 likely false alarms, 5 duplicates.

### Issues to fix
| Severity | Location | Issue | Suggested fix |
|---|---|---|---|
| HIGH | `app/admin.py:26` | The code uses shell=True for a subprocess call, which allows for command injection and potential security vulnerabilities. | Disable the use of shell=True for subprocess calls and use alternative methods for network communication. |
| HIGH | `app/admin.py:41` | MD5 is a known weak cryptographic hash function, making it unsuitable for password hashing. | Replace the MD5 hash function with a stronger algorithm like bcrypt or scrypt. |
| HIGH | `app/auth.py:23` | The code directly hardcodes the JWT secret, which is a security risk. | Store the JWT secret in an environment variable or a secure secrets management system. |
| HIGH | `app/auth.py:27` | The code is intentionally bypassing JWT verification, which is a security risk as it allows for potential token tampering. | Enable JWT verification by setting `verify_signature=True` in the `jwt.decode` function. |
| HIGH | `app/upload.py:26` | The `extractall` method without validation could allow arbitrary files to be extracted, potentially exposing sensitive data or system vulnerabilities. | Validate the archive path and only extract files from trusted sources. |
| MEDIUM | `app/admin.py:20` | The code directly inserts user input into the SQL query, creating a potential SQL injection vulnerability. | Use parameterized queries to prevent user input from being directly inserted into the SQL query. |
| MEDIUM | `app/admin.py:31` | The code directly deserializes untrusted data using `pickle.loads`, which is a known security vulnerability. | Use a safer deserialization method like `json.loads` or `ast.literal_eval` instead of `pickle.loads` to deserialize untrusted data. |
| MEDIUM | `app/admin.py:36` | The code uses `eval` to execute user-provided expressions, which is a known security vulnerability. | Replace `eval` with a safer alternative like `ast.literal_eval` for handling user-provided data. |
| MEDIUM | `app/upload.py:21` | The `yaml.load()` function is vulnerable to arbitrary object instantiation, allowing attackers to execute arbitrary code. | Replace `yaml.load(text)` with `yaml.safe_load(text)` to mitigate the risk of arbitrary object instantiation. |
| LOW | `app/admin.py:14` | The code directly hardcodes the password, which is a clear security risk. | Use a secure method like environment variables or a configuration file to store the password. |

### Dismissed as false alarms
- `app/auth.py:31` (B324 hashlib) — The SHA1 algorithm is deprecated and considered insecure. However, the code is not using it for any sensitive operations.
- `app/auth.py:35` (B501 request_with_no_cert_validation) — The code snippet does not explicitly disable SSL certificate checks, and the `verify=False` argument is used for a specific purpose (e.g., testing or specific …
- `app/auth.py:18` (B608 hardcoded_sql_expressions) — The code uses parameterized queries, mitigating the risk of SQL injection.
- `app/auth.py:43` (B108 hardcoded_tmp_directory) — The code is using a hardcoded directory, but it's not inherently insecure. It's a common practice to use a temporary directory for various reasons.
- `app/upload.py:30` (B108 hardcoded_tmp_directory) — The code is using a hardcoded directory, but it's not inherently insecure.
- `app/admin.py:9` (B403 blacklist) — The code snippet does not explicitly use the pickle module for any sensitive operations, and the mention of a security vulnerability is not directly related to…
- `app/admin.py:11` (B404 blacklist) — The code imports the subprocess module, which is a common practice for interacting with external processes. The message is not specific to a security vulnerabi…

_Triage by a local LLM. Treat as a first pass, not the final word._
