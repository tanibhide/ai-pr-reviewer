## Security review

Found **22** possible issues: 8 high, 11 medium, 3 low.

| Severity | Tool | Rule | Location | Issue |
|---|---|---|---|---|
| HIGH | bandit | B602 subprocess_popen_with_shell_equals_true | `app/admin.py:26` | subprocess call with shell=True identified, security issue. |
| HIGH | semgrep | subprocess-shell-true | `app/admin.py:26` | Found 'subprocess' function 'run' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doin… |
| HIGH | bandit | B324 hashlib | `app/admin.py:41` | Use of weak MD5 hash for security. Consider usedforsecurity=False |
| HIGH | semgrep | jwt-python-hardcoded-secret | `app/auth.py:23` | Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definition… |
| HIGH | semgrep | unverified-jwt-decode | `app/auth.py:27` | Detected JWT token decoded with 'verify=False'. This bypasses any integrity checks for the token which means the token could be tampered wi… |
| HIGH | bandit | B324 hashlib | `app/auth.py:31` | Use of weak SHA1 hash for security. Consider usedforsecurity=False |
| HIGH | bandit | B501 request_with_no_cert_validation | `app/auth.py:35` | Call to requests with verify=False disabling SSL certificate checks, security issue. |
| HIGH | bandit | B202 tarfile_unsafe_members | `app/upload.py:26` | tarfile.extractall used without any validation. Please check and discard dangerous members. |
| MEDIUM | bandit | B608 hardcoded_sql_expressions | `app/admin.py:20` | Possible SQL injection vector through string-based query construction. |
| MEDIUM | bandit | B301 blacklist | `app/admin.py:31` | Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue. |
| MEDIUM | bandit | B307 blacklist | `app/admin.py:36` | Use of possibly insecure function - consider using safer ast.literal_eval. |
| MEDIUM | semgrep | insecure-hash-algorithm-md5 | `app/admin.py:41` | Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic s… |
| MEDIUM | semgrep | md5-used-as-password | `app/admin.py:41` | It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a sh… |
| MEDIUM | bandit | B608 hardcoded_sql_expressions | `app/auth.py:18` | Possible SQL injection vector through string-based query construction. |
| MEDIUM | semgrep | insecure-hash-algorithm-sha1 | `app/auth.py:31` | Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic… |
| MEDIUM | bandit | B113 request_without_timeout | `app/auth.py:35` | Call to requests without timeout |
| MEDIUM | bandit | B108 hardcoded_tmp_directory | `app/auth.py:43` | Probable insecure usage of temp file/directory. |
| MEDIUM | bandit | B506 yaml_load | `app/upload.py:21` | Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load(). |
| MEDIUM | bandit | B108 hardcoded_tmp_directory | `app/upload.py:30` | Probable insecure usage of temp file/directory. |
| LOW | bandit | B403 blacklist | `app/admin.py:9` | Consider possible security implications associated with pickle module. |
| LOW | bandit | B404 blacklist | `app/admin.py:11` | Consider possible security implications associated with the subprocess module. |
| LOW | bandit | B105 hardcoded_password_string | `app/admin.py:14` | Possible hardcoded password: 'SuperSecret123!' |

_These are raw scanner results. Some may be false alarms._
