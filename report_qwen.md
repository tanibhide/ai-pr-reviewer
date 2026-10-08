## Security review (AI triage)

The scanners reported **11** findings. After triage: **5 to fix**, 3 likely false alarms, 3 duplicates.

### Issues to fix
| Severity | Location | Issue | Suggested fix |
|---|---|---|---|
| HIGH | `app/admin.py:26` | The code uses subprocess.run with shell=True, which can lead to command injection if the input is not properly sanitized. | Replace subprocess.run with subprocess.Popen and ensure that the command is constructed safely, or use subprocess.run with appropriate arguments to avoid shell… |
| HIGH | `app/admin.py:41` | The use of MD5 for password hashing is insecure and should be avoided as it is considered far too weak for security purposes. | Replace hashlib.md5 with a stronger hashing algorithm such as bcrypt or sha256. |
| MEDIUM | `app/admin.py:20` | The code uses a direct string-based query construction with user input, which is vulnerable to SQL injection. The use of f-string with single quotes around the… | Use parameterized queries to prevent SQL injection. Replace the f-string with a parameterized query using the `conn.execute(query, (username,))` syntax. |
| MEDIUM | `app/admin.py:31` | The code uses pickle.loads() to deserialize untrusted data, which is a known security vulnerability. | Replace pickle.loads() with a safer method like json.loads() for deserializing untrusted data. |
| LOW | `app/admin.py:14` | The password is hardcoded in the code, which is a security risk. | Remove the hardcoded password and use a secure method to manage passwords, such as environment variables or a configuration file. |

### Dismissed as false alarms
- `app/admin.py:36` (B307 blacklist) — The scanner's advice is to use safer methods like ast.literal_eval, but the code uses eval which is not safer and is already a known vulnerability. The code is…
- `app/admin.py:9` (B403 blacklist) — The code is using pickle for serialization and deserialization, which is not inherently insecure. However, it is not used in a way that poses a direct security…
- `app/admin.py:11` (B404 blacklist) — The scanner's message is about the subprocess module, but the code does not use subprocess in a way that could lead to security issues such as command injectio…

_Triage by a local LLM. Treat as a first pass, not the final word._
