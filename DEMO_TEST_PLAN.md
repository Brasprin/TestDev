# TestDev Security Requirements - Demo Test Plan

## 1.0 Pre-Demo Requirements: Test Accounts Setup

### 1.1.1 Website Administrator Account

```
First Name: Admin
Last Name: User
Email: admin@testdev.edu
Password: AdminPass123!
Role: ADMIN
Security Questions:
  Q1: What is the name of your first pet?
  A1: Fluffy
  Q2: What is your mother's maiden name?
  A2: Johnson
  Q3: What street did you grow up on?
  A3: Maple Street
```

### 1.1.2 Role A (Teacher/Product Manager)

```
First Name: John
Last Name: Educator
Email: teacher@testdev.edu
Password: TeacherPass123!
Role: TEACHER
Security Questions:
  Q1: What is the name of your first nephew or niece?
  A1: Emma
  Q2: What was the model of your first car?
  A2: Honda Civic
  Q3: What city were you born in?
  A3: Portland
```

### 1.1.3 Role B (Student/Customer)

```
First Name: Jane
Last Name: Scholar
Email: student@testdev.edu
Password: StudentPass123!
Role: STUDENT
Security Questions:
  Q1: What was the first concert you attended?
  A1: The Beatles
  Q2: What is the name of your first best friend from childhood?
  A2: Michael
  Q3: What is the name of the first pet?
  A3: Buddy
```

---

## 2.0 Demo Test Scenarios

### 2.1 Authentication Tests

#### 2.1.1 Require Authentication for All Pages

**Test Steps:**

1. Open browser and navigate to http://localhost:3000
2. Try to access protected routes without logging in:
   - http://localhost:3000/#/me/change-password
   - http://localhost:3000/#/admin/users
   - http://localhost:3000/#/faculty/courses
3. Verify: Should redirect to login or show "Unauthorized" message

**Expected Result:** ✅ All protected pages require authentication

---

#### 2.1.2 Cryptographically Strong One-Way Salted Hashes

**Test Steps:**

1. Check MONGODB PasswordHash

**Expected Result:** ✅ Password stored as bcrypt hash with salt rounds = 10

**Sample Hash Output:**

```
passwordHash: "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36P4/KFm"
```

---

#### 2.1.3 Generic Authentication Failure Messages

**Test Steps:**

1. Try login with non-existent email: `nonexistent@test.com` / `AnyPass123!`
   - **Response:** `{ error: "invalid credentials" }`
2. Try login with correct email but wrong password: `admin@testdev.edu` / `WrongPass123!`
   - **Response:** `{ error: "invalid credentials" }`
3. Try login with locked account (after 5 failed attempts)
   - **Response:** `{ error: "invalid credentials", lockout: {...} }`

**Expected Result:** ✅ All failures return generic message, no indication of which field failed

---

#### 2.1.4 Password Complexity Requirements

**Test Steps:**

1. Try registering with weak passwords:
   - `password123` (no uppercase, no special char) → ❌ Rejected
   - `PASSWORD123` (no lowercase, no special char) → ❌ Rejected
   - `Password123` (no special char) → ❌ Rejected
   - `Password!` (no number) → ❌ Rejected
2. Try registering with valid password:
   - `ValidPass123!` → ✅ Accepted

**Expected Result:** ✅ Regex enforces: uppercase + lowercase + digit + special char

**Regex Pattern:**

```
/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/
```

---

#### 2.1.5 Password Length Requirements

**Test Steps:**

1. Try registering with short passwords:
   - `Pass1!` (6 chars) → ❌ Rejected
   - `Pass12!` (7 chars) → ❌ Rejected
2. Try registering with minimum length:
   - `Pass123!` (8 chars) → ✅ Accepted

**Expected Result:** ✅ Minimum 8 characters enforced

---

#### 2.1.6 Password Entry Obscured on Screen

**Test Steps:**

1. Navigate to login page: http://localhost:3000/#/login
2. Click on password input field
3. Type password: `TestPass123!`
4. Verify: Characters display as dots/asterisks (●●●●●●●●●●●●)
5. Click eye icon to toggle visibility
6. Verify: Password becomes visible as plain text

**Expected Result:** ✅ Password field uses `type="password"` with visibility toggle

---

#### 2.1.7 Account Lockout After Failed Attempts

**Test Steps:**

1. Navigate to login page
2. Attempt login 5 times with wrong password for `admin@testdev.edu`:
   - Attempt 1: `{ error: "invalid credentials", attemptsRemaining: 4 }`
   - Attempt 2: `{ error: "invalid credentials", attemptsRemaining: 3 }`
   - Attempt 3: `{ error: "invalid credentials", attemptsRemaining: 2 }`
   - Attempt 4: `{ error: "invalid credentials", attemptsRemaining: 1 }`
   - Attempt 5: `{ error: "invalid credentials", lockout: { until: "2024-01-15T10:30:00Z", secondsRemaining: 600 } }`
3. Try login immediately after lockout
   - **Response:** `{ error: "invalid credentials" }` (no indication of lockout)
4. Wait 10 minutes (or check database for lockUntil timestamp)
5. Try login again with correct password
   - **Response:** ✅ Login successful

**Expected Result:** ✅ Account locked for 10 minutes after 5 failed attempts

**Database State During Lockout:**

```javascript
{
  email: "admin@testdev.edu",
  failedLoginCount: 0,  // Reset after lock
  lockUntil: ISODate("2024-01-15T10:30:00Z"),
  lastFailedLoginAt: ISODate("2024-01-15T10:20:00Z")
}
```

---

#### 2.1.8 Random Security Questions

**Test Steps:**

1. During registration, verify security questions are from approved pool
2. Check that questions like "What is your favorite book?" are NOT in the pool
3. Verify questions in pool have high-entropy answers:
   - ✅ "What is the name of your first employer?" (varies widely)
   - ✅ "What was the name of your first sports coach?" (varies widely)
   - ❌ "What is your favorite book?" (common answers like "The Bible")

**Expected Result:** ✅ 20 high-entropy questions available

**Question Pool:**

```
1. What is the name of your first employer?
2. What was the name of your childhood best friend?
3. What is the name of the street you lived on in third grade?
4. What was the name of your first teacher?
5. What is the name of your first pet's veterinarian?
6. What was the name of your first sports coach?
7. What is the name of the city where your mother was born?
8. What was the name of your first band or musical group?
9. What is the name of your first significant other?
10. What was the name of your first car?
... (10 more)
```

---

#### 2.1.9 Prevent Password Reuse

**Test Steps:**

1. Login as `admin@testdev.edu` with password `AdminPass123!`
2. Navigate to: http://localhost:3000/#/me/change-password
3. Try to change password to same password:
   - Current: `AdminPass123!`
   - New: `AdminPass123!`
   - **Response:** ❌ `{ error: "password reuse not allowed" }`
4. Try to change to a previously used password (from history):
   - New: `OldPassword123!` (if it was used before)
   - **Response:** ❌ `{ error: "password reuse not allowed" }`
5. Change to new password:
   - New: `NewPassword123!`
   - **Response:** ✅ `{ ok: true }`

**Expected Result:** ✅ System maintains password history (last 5) and prevents reuse

**Database State:**

```javascript
{
  email: "admin@testdev.edu",
  passwordHash: "$2b$10$...(NewPassword123!)",
  passwordHistory: [
    "$2b$10$...(AdminPass123!)",
    "$2b$10$...(PreviousPass123!)",
    // ... up to 5 previous hashes
  ]
}
```

---

#### 2.1.10 Minimum Password Age (24 Hours)

**Test Steps:**

1. Login as `admin@testdev.edu`
2. Change password to `NewPass123!`
3. Immediately try to change password again to `AnotherPass123!`
   - **Response:** ❌ `{ error: "password recently changed", nextChangeTime: "2024-01-16T10:20:00Z", secondsRemaining: 86400 }`
4. Wait 24 hours (or modify system time for testing)
5. Try to change password again
   - **Response:** ✅ `{ ok: true }`

**Expected Result:** ✅ Cannot change password within 24 hours of last change

---

#### 2.1.11 Last Login/Failed Attempt Reporting

**Test Steps:**

1. Login as `student@testdev.edu` for the first time
   - **Response includes:** `{ lastLoginAt: null, lastFailedLoginAt: null }`
2. Logout and login again
   - **Response includes:** `{ lastLoginAt: "2024-01-15T09:00:00Z", lastFailedLoginAt: null }`
3. Navigate to home page: http://localhost:3000/#/
4. Verify account activity displayed:
   - "✓ Last successful login: 1/15/2024, 10:20:00 AM"
   - "⚠ Last failed login attempt: 1/15/2024, 09:50:00 AM" (if applicable)

**Expected Result:** ✅ Previous login/failed attempt timestamps displayed on next login

---

#### 2.1.12 Re-authentication for Critical Operations

**Test Steps:**

1. Login as `admin@testdev.edu`
2. Navigate to: http://localhost:3000/#/me/change-password
3. Try to change password without re-authenticating:
   - Current: `AdminPass123!`
   - New: `NewPass123!`
   - **Response:** ✅ `{ ok: true }` (works because it requires current password)
4. Navigate to: http://localhost:3000/#/me/change-password
5. Click "Revoke All Sessions" button
   - **Response:** ❌ `{ error: "reauth_required" }`
6. Redirected to: http://localhost:3000/#/reauthenticate
7. Enter password: `AdminPass123!`
   - **Response:** ✅ Redirected back to change-password page
8. Click "Revoke All Sessions" again
   - **Response:** ✅ `{ ok: true }`

**Expected Result:** ✅ Critical operations require re-authentication within 10-minute window

---

### 2.2 Authorization/Access Control Tests

#### 2.2.1 Single Site-Wide Authorization Component

**Test Steps:**

1. Examine code: `services/auth/src/index.js`
2. Verify `requireAuth()` middleware used on all protected endpoints
3. Verify `requireRole()` middleware used for role-based access
4. Check that all services use same pattern

**Expected Result:** ✅ Centralized middleware in `packages/common/index.js`

**Code Pattern:**

```javascript
function requireAuth(req, res, next) { ... }
function requireRole(...roles) { ... }

// Usage
app.get("/protected", requireAuth, requireRole("ADMIN"), handler);
```

---

#### 2.2.2 Secure Error Handling

**Test Steps:**

1. Try to access admin endpoint as student:
   - **Response:** `{ error: "Forbidden" }` (HTTP 403)

**Expected Result:** ✅ All errors return generic messages without stack traces

---

#### 2.2.3 Role-Based Access Control

**Test Steps:**

1. Login as `student@testdev.edu`
2. Try to access: http://localhost:3000/#/admin/users
   - **Response:** ❌ `{ error: "Forbidden" }`
3. Try to access: http://localhost:3000/#/faculty/courses
   - **Response:** ❌ `{ error: "Forbidden" }`
4. Try to access: http://localhost:3000/#/me/grades
   - **Response:** ✅ Allowed (student can view own grades)
5. Login as `teacher@testdev.edu`
6. Try to access: http://localhost:3000/#/faculty/courses
   - **Response:** ✅ Allowed (teacher can create courses)
7. Login as `admin@testdev.edu`
8. Try to access: http://localhost:3000/#/admin/users
   - **Response:** ✅ Allowed (admin can manage users)

**Expected Result:** ✅ Each role can only access their designated features

---

### 2.3 Data Validation Tests

#### 2.3.1 Input Rejection (No Sanitization)

**Test Steps:**

1. Try to register with SQL injection attempt:
   - Email: `test@test.com'; DROP TABLE users; --`
   - **Response:** ❌ `{ error: "Invalid input" }`
2. Try to register with XSS attempt:
   - First Name: `<script>alert('xss')</script>`
   - **Response:** ❌ `{ error: "First name required" }` or validation error
3. Try to create course with invalid capacity:
   - Capacity: `-5`
   - **Response:** ❌ `{ error: "capacity must be positive" }`

**Expected Result:** ✅ Invalid input rejected, not sanitized

---

#### 2.3.2 Numeric Range & Character Set Validation

**Test Steps:**

1. Try to create course with invalid capacity:
   - Capacity: `-10` → ❌ Rejected
   - Capacity: `0` → ❌ Rejected
   - Capacity: `100` → ✅ Accepted
2. Try to assign invalid grade:
   - Grade: `5.5` → ❌ Rejected (not in allowed set)
   - Grade: `4.0` → ✅ Accepted
   - Grade: `W` → ✅ Accepted (withdrawal)

**Expected Result:** ✅ Numeric ranges and character sets validated

**Allowed Grades:**

```
['4.0', '3.5', '3.0', '2.5', '2.0', '1.5', '1.0', '0.0', 'W']
```

---

#### 2.3.3 Text Length Validation

**Test Steps:**

1. Try to register with empty first name:
   - First Name: `` (empty)
   - **Response:** ❌ `{ error: "First name required" }`
2. Try to search users with very long query:
   - Query: `${'a'.repeat(200)}`
   - **Response:** ❌ `{ error: "query too long" }`
3. Register with valid names:
   - First Name: `John` → ✅ Accepted
   - Last Name: `Doe` → ✅ Accepted

**Expected Result:** ✅ Text length validated (min 1, max 100 for queries)

---

### 2.4 Error Handling and Logging Tests

#### 2.4.1 No Debug/Stack Trace Information

**Test Steps:**

1. Trigger a server error (e.g., invalid MongoDB operation)
2. Check response:
   - **Should NOT contain:** Stack trace, file paths, line numbers
   - **Should contain:** Generic error message like `{ error: "operation failed" }`
3. Check server logs (not sent to client):
   - **Should contain:** Full error details for debugging

**Expected Result:** ✅ Clients receive generic errors, server logs contain details

---

#### 2.4.2 Generic Error Messages & Custom Error Pages

**Test Steps:**

1. Navigate to non-existent route: http://localhost:3000/#/invalid-page
   - **Response:** `<div class="alert error">Not Found</div>`
2. Try to access protected resource without auth:
   - **Response:** `<div class="alert error">Unauthorized</div>`
3. Trigger validation error:
   - **Response:** `<div class="alert error">Invalid input</div>`

**Expected Result:** ✅ All errors use generic messages

---

#### 2.4.3 Admin-Only Log Access

**Test Steps:**

1. Login as `student@testdev.edu`
2. Try to access audit logs: `GET http://localhost:8005/audit`
   - **Response:** ❌ `{ error: "Forbidden" }` (HTTP 403)
3. Login as `admin@testdev.edu`
4. Access audit logs: `GET http://localhost:8005/audit`
   - **Response:** ✅ Returns audit log entries
5. Query specific action: `GET http://localhost:8005/audit?action=LOGIN_SUCCESS`
   - **Response:** ✅ Returns filtered logs

**Expected Result:** ✅ Only admins can access audit logs

---

#### 2.4.4 Log All Validation Failures

**Test Steps:**

1. Try to register with invalid password
2. Check audit logs: `GET http://localhost:8005/audit?action=VALIDATION_FAILURE`
3. Verify log entry contains:
   ```json
   {
     "action": "VALIDATION_FAILURE",
     "entityType": "ValidationError",
     "entityId": "password",
     "metadata": {
       "field": "password",
       "reason": "does not meet complexity requirements",
       "endpoint": "/auth/register",
       "method": "POST"
     },
     "severity": "INFO",
     "status": "FAILURE"
   }
   ```

**Expected Result:** ✅ All validation failures logged with details

---

#### 2.4.5 Log All Authentication Attempts

**Test Steps:**

1. Successful login as `admin@testdev.edu`
2. Check audit logs: `GET http://localhost:8005/audit?action=LOGIN_SUCCESS`
3. Verify log entry:
   ```json
   {
     "action": "LOGIN_SUCCESS",
     "actorId": "user_id",
     "actorRole": "ADMIN",
     "entityType": "Authentication",
     "metadata": {
       "email": "admin@testdev.edu",
       "previousLoginAt": "2024-01-14T10:00:00Z",
       "ip": "127.0.0.1",
       "userAgent": "Mozilla/5.0..."
     },
     "severity": "INFO",
     "status": "SUCCESS"
   }
   ```
4. Failed login attempt
5. Check audit logs: `GET http://localhost:8005/audit?action=LOGIN_FAILURE`
6. Verify log entry:
   ```json
   {
     "action": "LOGIN_FAILURE",
     "actorId": "user_id",
     "actorRole": "STUDENT",
     "entityType": "Authentication",
     "metadata": {
       "email": "student@testdev.edu",
       "attemptNumber": 1,
       "locked": false,
       "ip": "127.0.0.1",
       "userAgent": "Mozilla/5.0..."
     },
     "severity": "WARNING",
     "status": "FAILURE"
   }
   ```
7. Account lockout after 5 attempts
8. Check audit logs: `GET http://localhost:8005/audit?action=ACCOUNT_LOCKED`
9. Verify log entry:
   ```json
   {
     "action": "ACCOUNT_LOCKED",
     "actorId": "user_id",
     "actorRole": "STUDENT",
     "entityType": "Authentication",
     "metadata": {
       "email": "student@testdev.edu",
       "reason": "Too many failed login attempts (5)",
       "lockoutDuration": "10 minutes",
       "ip": "127.0.0.1",
       "userAgent": "Mozilla/5.0..."
     },
     "severity": "WARNING",
     "status": "FAILURE"
   }
   ```

**Expected Result:** ✅ All auth attempts (success, failure, lockout) logged

---

#### 2.4.6 Log All Access Control Failures

**Test Steps:**

1. Login as `student@testdev.edu`
2. Try to access admin endpoint: `GET http://localhost:8001/auth/users/list`
3. Check audit logs: `GET http://localhost:8005/audit?action=ACCESS_DENIED_ROLE`
4. Verify log entry:
   ```json
   {
     "action": "ACCESS_DENIED_ROLE",
     "actorId": "student_user_id",
     "actorRole": "STUDENT",
     "entityType": "Authorization",
     "entityId": "/auth/users/list",
     "metadata": {
       "requiredRoles": ["ADMIN"],
       "userRole": "STUDENT",
       "endpoint": "/auth/users/list",
       "method": "GET",
       "ip": "127.0.0.1"
     },
     "severity": "WARNING",
     "status": "FAILURE"
   }
   ```

**Expected Result:** ✅ All authorization failures logged

---

## 3.0 Testing Checklist

### Pre-Demo Setup

- [ ] Create 3 test accounts (Admin, Teacher, Student)
- [ ] Start MongoDB service
- [ ] Start all microservices (npm run dev in each)
- [ ] Start frontend (npm start)
- [ ] Verify all services are running on correct ports

### Authentication Tests

- [ ] 2.1.1 - Protected pages require authentication
- [ ] 2.1.2 - Passwords stored as bcrypt hashes
- [ ] 2.1.3 - Generic failure messages
- [ ] 2.1.4 - Password complexity enforced
- [ ] 2.1.5 - Password length enforced (min 8)
- [ ] 2.1.6 - Password field obscured with toggle
- [ ] 2.1.7 - Account lockout after 5 attempts (10 min)
- [ ] 2.1.8 - High-entropy security questions
- [ ] 2.1.9 - Password reuse prevented
- [ ] 2.1.10 - 24-hour minimum password age
- [ ] 2.1.11 - Last login/failed attempt reported
- [ ] 2.1.12 - Re-authentication for critical ops

### Authorization Tests

- [ ] 2.2.1 - Centralized auth component
- [ ] 2.2.2 - Secure error handling
- [ ] 2.2.3 - Role-based access control

### Data Validation Tests

- [ ] 2.3.1 - Input rejection (no sanitization)
- [ ] 2.3.2 - Numeric range validation
- [ ] 2.3.3 - Text length validation

### Logging Tests

- [ ] 2.4.1 - No debug info in responses
- [ ] 2.4.2 - Generic error messages
- [ ] 2.4.3 - Admin-only log access
- [ ] 2.4.4 - Validation failures logged
- [ ] 2.4.5 - Auth attempts logged
- [ ] 2.4.6 - Access control failures logged

---

## 4.0 API Testing Commands (cURL)

### Register Test Account

```bash
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!",
    "firstName": "Test",
    "lastName": "User",
    "securityQuestionsAnswers": [
      {"question": "What is the name of your first employer?", "answer": "TechCorp"},
      {"question": "What was the name of your first teacher?", "answer": "Mrs. Smith"},
      {"question": "What is the name of the city where your mother was born?", "answer": "Boston"}
    ]
  }'
```

### Login Test

```bash
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "admin@testdev.edu",
    "password": "AdminPass123!"
  }'
```

### Access Audit Logs (Admin Only)

```bash
curl -X GET "http://localhost:8005/audit?action=LOGIN_SUCCESS" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Test Failed Login Attempts

```bash
# Attempt 1-5 with wrong password
for i in {1..5}; do
  curl -X POST http://localhost:8001/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "email": "admin@testdev.edu",
      "password": "WrongPassword123!"
    }'
  echo "Attempt $i"
  sleep 1
done
```

### Change Password

```bash
curl -X POST http://localhost:8001/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "currentPassword": "AdminPass123!",
    "newPassword": "NewAdminPass123!",
    "forceLogoutAllSessions": false
  }'
```

---

## 5.0 MongoDB Queries for Verification

### Check User Password Hash

```javascript
db.users.findOne({ email: "admin@testdev.edu" }, { passwordHash: 1 });
```

### Check Password History

```javascript
db.users.findOne({ email: "admin@testdev.edu" }, { passwordHistory: 1 });
```

### Check Account Lockout Status

```javascript
db.users.findOne(
  { email: "admin@testdev.edu" },
  { lockUntil: 1, failedLoginCount: 1 }
);
```

### Check Last Login Info

```javascript
db.users.findOne(
  { email: "admin@testdev.edu" },
  { lastLoginAt: 1, lastFailedLoginAt: 1 }
);
```

### View Audit Logs

```javascript
db.audits.find({ action: "LOGIN_SUCCESS" }).sort({ timestamp: -1 }).limit(10);
db.audits.find({ action: "LOGIN_FAILURE" }).sort({ timestamp: -1 }).limit(10);
db.audits.find({ action: "ACCOUNT_LOCKED" }).sort({ timestamp: -1 }).limit(10);
db.audits
  .find({ action: "VALIDATION_FAILURE" })
  .sort({ timestamp: -1 })
  .limit(10);
```

### Check Session Management

```javascript
db.sessions.find({ revokedAt: null }).sort({ issuedAt: -1 }).limit(10);
```

---

## 6.0 Expected Outcomes Summary

| Requirement | Implementation                                 | Status                  |
| ----------- | ---------------------------------------------- | ----------------------- |
| 2.1.1       | JWT middleware on all protected routes         | ✅ Complete             |
| 2.1.2       | bcryptjs with 10 salt rounds                   | ✅ Complete             |
| 2.1.3       | Generic "invalid credentials" message          | ✅ Complete             |
| 2.1.4       | Regex: uppercase + lowercase + digit + special | ✅ Complete             |
| 2.1.5       | Minimum 8 characters                           | ✅ Complete             |
| 2.1.6       | HTML type="password" with toggle               | ✅ Complete             |
| 2.1.7       | 5 attempts → 10 min lockout                    | ✅ Complete             |
| 2.1.8       | 20 high-entropy questions                      | ✅ Complete             |
| 2.1.9       | Password history (last 5)                      | ✅ Complete             |
| 2.1.10      | 24-hour minimum age                            | ✅ Complete             |
| 2.1.11      | Last login/failed attempt reported             | ✅ Complete             |
| 2.1.12      | Re-auth for critical ops (10 min window)       | ✅ Complete             |
| 2.2.1       | Centralized requireAuth/requireRole            | ✅ Complete             |
| 2.2.2       | Generic error messages (no stack traces)       | ✅ Complete             |
| 2.2.3       | Role-based access control                      | ✅ Complete             |
| 2.3.1       | Input rejection (no sanitization)              | ✅ Complete             |
| 2.3.2       | Numeric range & character set validation       | ✅ Complete             |
| 2.3.3       | Text length validation                         | ✅ Complete             |
| 2.4.1       | No debug info in responses                     | ✅ Complete             |
| 2.4.2       | Generic error messages                         | ✅ Complete             |
| 2.4.3       | Admin-only audit log access                    | ✅ Complete             |
| 2.4.4       | Validation failures logged                     | ✅ Implemented          |
| 2.4.5       | Auth attempts logged                           | ✅ Implemented          |
| 2.4.6       | Access control failures logged                 | ✅ Infrastructure Ready |
