# Simple Authentication System 🔐

This is a basic **Flask-based JWT Authentication System** that allows users to register, log in, and access protected routes using secure token-based sessions. It demonstrates core web authentication concepts such as form validation, hashed password storage, token expiration, and route protection.

---

## 🔧 Features

- 📝 User Registration with duplicate username prevention  
- 🔐 Secure login using SHA-256 hashed passwords  
- ✅ JWT-based authentication system with token expiration  
- 🔒 Route protection based on authentication status  
- 🌐 Flash messages and browser feedback  
- 🧪 Tested on both normal and incognito browser modes  

---

## 🗂️ Project Structure


---

## 💡 How It Works

1. **Register a new user:**  
   - System checks for duplicate usernames before saving.  
   - Passwords are hashed with SHA-256 before being stored.

2. **Login process:**  
   - On valid login, a JWT token is generated and stored in cookies.  
   - Token includes expiry to enhance security.

3. **Protected route `/protected`:**  
   - Only accessible when a valid token is present.  
   - Expired or missing tokens redirect to login.

4. **Session Behavior Tested in CMD Logs:**  
   - CMD logs capture requests and redirects for various actions like invalid login, token expiry, and access attempts without login.

---

## 🛡️ Security Notes

- SHA-256 hashing is used, but can be improved by using `bcrypt` or `argon2`.  
- Adding a salt to the password before hashing will further strengthen protection.

---

