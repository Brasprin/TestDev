const state = {
  accessToken: null,
  user: null,
  lastLoginAttempts: null,
  lockoutInfo: null, // in-memory only for current page session
  userActivity: null, // { lastLoginAt, lastFailedLoginAt }
};

// Removed localStorage persistence for lockout state per requirement
function saveLockoutInfo() {
  /* no-op: do not persist across refresh */
}

const services = {
  auth: "http://localhost:8001",
  users: "http://localhost:8002",
  courses: "http://localhost:8003",
  grades: "http://localhost:8004",
  audit: "http://localhost:8005",
};

function setAccessToken(token) {
  state.accessToken = token;
  render();
}
function setUser(user) {
  state.user = user;
  if (user) {
    sessionStorage.setItem("user", JSON.stringify(user));
  } else {
    sessionStorage.removeItem("user");
  }
  render();
}
// Internal setters used during bootstrap to avoid extra renders
function setAccessTokenNoRender(token) {
  state.accessToken = token;
}
function setUserNoRender(user) {
  state.user = user;
}

// Restore persisted user and activity from sessionStorage at startup
try {
  const savedUserRaw = sessionStorage.getItem("user");
  if (savedUserRaw) state.user = JSON.parse(savedUserRaw);
} catch {}
try {
  const savedActRaw = sessionStorage.getItem("userActivity");
  if (savedActRaw) state.userActivity = JSON.parse(savedActRaw);
} catch {}

async function initAuth() {
  try {
    const rr = await fetch(`${services.auth}/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    if (rr.ok) {
      const { accessToken } = await rr.json();
      setAccessTokenNoRender(accessToken);

      const meRes = await api(services.users, "/users/me");
      if (meRes.ok) {
        const me = await meRes.json();
        setUserNoRender(me);
      } else {
        setUserNoRender(null);
      }
    } else {
      // 401 is expected when user is not logged in - don't treat as error
      setAccessTokenNoRender(null);
      setUserNoRender(null);
    }
  } catch (e) {
    // Network errors are expected during init - silently fail
    setAccessTokenNoRender(null);
    setUserNoRender(null);
  } finally {
    render();
  }
}

async function api(base, path, opts = {}) {
  try {
    const headers = opts.headers || {};
    if (state.accessToken)
      headers["Authorization"] = `Bearer ${state.accessToken}`;
    const res = await fetch(`${base}${path}`, {
      ...opts,
      headers,
      credentials: "include",
    });
    if (
      res.status === 401 &&
      base !== services.auth &&
      path !== "/auth/refresh"
    ) {
      const rr = await fetch(`${services.auth}/auth/refresh`, {
        method: "POST",
        credentials: "include",
      });
      if (rr.ok) {
        const { accessToken } = await rr.json();
        setAccessToken(accessToken);
        return api(base, path, opts);
      }
    }
    return res;
  } catch (e) {
    // Return a failed response object instead of throwing
    return { ok: false, status: 0, error: "Network error" };
  }
}

async function getCourseMap() {
  const res = await api(services.courses, "/courses");
  if (!res.ok) return {};
  const courses = await res.json();
  const map = {};
  for (const c of courses) map[c._id] = c;
  return map;
}

function nav() {
  const links = [];
  links.push(`<a href="#/">Home</a>`);
  if (!state.user) {
    links.push(`<a href="#/login">Login</a>`);
    links.push(`<a href="#/register">Register</a>`);
  } else {
    links.push(`<a href="#/courses">Courses</a>`);
    if (state.user.role === "STUDENT") {
      links.push(`<a href="#/me/grades">My Grades</a>`);
      links.push(`<a href="#/me/enrollments">My Enrollments</a>`);
    }
    if (state.user.role === "TEACHER") {
      links.push(`<a href="#/faculty/courses">Create Courses</a>`);
    }
    if (state.user.role === "ADMIN") {
      links.push(`<a href="#/admin/users">User Mgmt</a>`);
      links.push(`<a href="#/admin/audit">Audit Logs</a>`);
      links.push(`<a href="#/admin/reset-password">Reset Password (Admin)</a>`);
    }
    links.push(`<a href="#/me/change-password">Change Password</a>`);
    links.push(`<a href="#/logout">Logout</a>`);
  }
  return links.join("");
}

// Global security question pool used across all forms
const SECURITY_QUESTION_POOL = [
  "What is the name of your first pet?",
  "What is your mother's maiden name?",
  "What street did you grow up on?",
  "What is the name of your first nephew or niece?",
  "What was the model of your first car?",
  "What city were you born in?",
  "What was the first concert you attended?",
  "What is the name of your first best friend from childhood?",
];

const PASSWORD_RULES = {
  len: { text: "Minimum 8 characters", test: (v) => v.length >= 8 },
  upper: {
    text: "At least one uppercase letter (A-Z)",
    test: (v) => /[A-Z]/.test(v),
  },
  lower: {
    text: "At least one lowercase letter (a-z)",
    test: (v) => /[a-z]/.test(v),
  },
  digit: { text: "At least one number (0-9)", test: (v) => /\d/.test(v) },
  special: {
    text: "At least one special character (!@#$%^&*)",
    test: (v) => /[^\w\s]/.test(v),
  },
};

function attachPasswordChecklist(passwordId, confirmId = null, hintId = null) {
  const pwdInput = document.getElementById(passwordId);
  const confirmInput = confirmId ? document.getElementById(confirmId) : null;
  if (!pwdInput) return;

  const hintContainer = hintId
    ? document.getElementById(hintId)
    : pwdInput.parentElement;

  const ul = document.createElement("ul");
  ul.className = "pwd-checklist";
  ul.style.margin = "8px 0 0 0";
  ul.style.padding = "0";
  ul.style.listStyle = "none";

  ul.innerHTML = `
    ${Object.entries(PASSWORD_RULES)
      .map(([rule]) => `<li data-rule="${rule}"></li>`)
      .join("")}
    <li data-rule="match"></li>
  `;
  hintContainer?.appendChild(ul);

  const setRule = (name, ok) => {
    const li = ul.querySelector(`[data-rule="${name}"]`);
    if (!li) return;

    li.style.color = ok ? "#2e7d32" : "#c62828";
    li.style.fontWeight = ok ? "600" : "400";

    const text = PASSWORD_RULES[name]?.text || "Passwords match";
    li.textContent = `${ok ? "✅" : "❌"} ${text}`;
  };

  const evalPwd = () => {
    const v = pwdInput.value || "";

    Object.entries(PASSWORD_RULES).forEach(([rule, { test }]) => {
      setRule(rule, test(v));
    });

    if (confirmInput) {
      const matchOk = confirmInput.value === v && v.length > 0;
      setRule("match", matchOk);
    }
  };

  pwdInput.addEventListener("input", evalPwd);
  confirmInput?.addEventListener("input", evalPwd);
  evalPwd();

  return { evalPwd, setRule };
}

function attachPasswordToggle(inputId, btnId) {
  const input = document.getElementById(inputId);
  const btn = document.getElementById(btnId);
  if (!btn) return;

  btn.onclick = () => {
    input.type = input.type === "password" ? "text" : "password";
  };
}

async function onRoute() {
  const hash = location.hash.slice(1) || "/";
  const app = document.getElementById("app");
  const container = (html) =>
    (app.innerHTML = `
    <header>
      <div>Distributed Enrollment</div>
      <nav>${nav()}</nav>
    </header>
    <div class="container">${html}</div>
    <footer>Localhost multi-node demo</footer>`);

  const savedUser = sessionStorage.getItem("user")
    ? JSON.parse(sessionStorage.getItem("user"))
    : null;

  if (hash === "/") {
    const userToShow = savedUser || state.user;
    const displayName =
      userToShow?.firstName && userToShow?.lastName
        ? `${userToShow.firstName} ${userToShow.lastName}`
        : userToShow?.email || "Guest";

    // Initialize homeHtml with welcome card
    let homeHtml = `<div class="card">Welcome ${displayName}!</div>`;

    // Show attempts remaining if available
    if (state.lastLoginAttempts !== null && state.lastLoginAttempts > 0) {
      homeHtml += `<div class="card" style="margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 3px solid #ff9800;">
        <strong>⚠ Login Attempts Remaining: ${state.lastLoginAttempts}</strong>
      </div>`;
    }

    // Show user activity if available
    if (state.userActivity) {
      let activityHtml = "<strong>Login Activity:</strong><br/>";

      if (state.userActivity.lastLoginAt) {
        const lastLogin = new Date(state.userActivity.lastLoginAt);
        activityHtml += `✓ Last successful login: ${lastLogin.toLocaleString()}<br/>`;
      } else {
        activityHtml += `✓ First login<br/>`;
      }

      if (state.userActivity.lastFailedLoginAt) {
        const lastFailed = new Date(state.userActivity.lastFailedLoginAt);
        activityHtml += `⚠ Last failed login attempt: ${lastFailed.toLocaleString()}`;
      }

      homeHtml += `<div class="card" style="margin-top: 15px; padding: 10px; background: #f0f8ff; border-left: 3px solid #0066cc;">
        ${activityHtml}
      </div>`;
    }

    return container(homeHtml);
  }

  if (hash === "/login") {
    return (
      container(`<div class="card">
      <h3>Login</h3>
      <input id="email" placeholder="Email" />
      <div class="field" style="position: relative;">
        <input id="password" placeholder="Password" type="password" style="padding-right: 35px;" />
        <button id="togglePassword" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      <button id="loginBtn">Login</button>
      <div id="msg"></div>
      <div id="lastActivityMsg" style="margin-top: 15px; padding: 10px; background: #f0f8ff; border-left: 3px solid #0066cc; display: none;"></div>
      <div style="margin-top: 10px; text-align: center;">
        <a href="#/forgot-password" style="color: #0066cc; text-decoration: none;">Forgot Password?</a>
      </div>
    </div>`),
      setTimeout(() => {
        // Password visibility toggle
        const toggleBtn = document.getElementById("togglePassword");
        const passwordInput = document.getElementById("password");
        const emailInput = document.getElementById("email");
        const loginBtn = document.getElementById("loginBtn");
        const msgDiv = document.getElementById("msg");
        let lockoutInterval = null;
        // On page load, do not restore any previous lockout; ensure clean state
        state.lockoutInfo = null;

        if (toggleBtn) {
          toggleBtn.onclick = (e) => {
            e.preventDefault();
            passwordInput.type =
              passwordInput.type === "password" ? "text" : "password";
          };
        }

        // Clear any in-memory lockout when email changes
        emailInput.addEventListener("input", () => {
          state.lockoutInfo = null;
          loginBtn.disabled = false;
          msgDiv.innerHTML = "";
          if (lockoutInterval) {
            clearInterval(lockoutInterval);
            lockoutInterval = null;
          }
        });

        // Do not restore countdown from previous attempts on page load

        loginBtn.onclick = async () => {
          const email = emailInput.value;
          const password = passwordInput.value;
          const res = await api(services.auth, "/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
          });
          if (res.ok) {
            const data = await res.json();
            state.lastLoginAttempts = null; // Clear attempts on successful login

            // Store activity information for display on home page
            state.userActivity = {
              lastLoginAt: data.lastLoginAt,
              lastFailedLoginAt: data.lastFailedLoginAt,
            };
            try {
              sessionStorage.setItem(
                "userActivity",
                JSON.stringify(state.userActivity)
              );
            } catch {}

            attachPasswordChecklist("password", null, "pwdHint");
            setAccessToken(data.accessToken);
            setUser(data.user);

            // Redirect to home page immediately
            location.hash = "#/";
          } else {
            try {
              const err = await res.json();
              if (typeof err.attemptsRemaining === "number") {
                state.lastLoginAttempts = err.attemptsRemaining;
              }
              if (
                err.lockout &&
                typeof err.lockout.secondsRemaining === "number"
              ) {
                // Store lockout info for persistence across page refreshes
                state.lockoutInfo = {
                  email: email,
                  secondsRemaining: err.lockout.secondsRemaining,
                  lockedAt: Date.now(),
                };

                let seconds = err.lockout.secondsRemaining;
                loginBtn.disabled = true;
                const fmt = (s) => {
                  const m = Math.floor(s / 60);
                  const sec = s % 60;
                  return `${m}:${sec.toString().padStart(2, "0")}`;
                };
                // Render only the lockout message (clear any previous messages)
                msgDiv.innerHTML = `<div class="alert error">Account locked. Try again in <span id="lockCountdown">${fmt(
                  seconds
                )}</span>.</div>`;
                lockoutInterval = setInterval(() => {
                  seconds -= 1;
                  if (seconds <= 0) {
                    clearInterval(lockoutInterval);
                    lockoutInterval = null;
                    loginBtn.disabled = false;
                    state.lockoutInfo = null;
                    msgDiv.innerHTML = `<div class="alert">You can try logging in again now.</div>`;
                  } else {
                    const el = document.getElementById("lockCountdown");
                    if (el) el.textContent = fmt(seconds);
                  }
                }, 1000);
              } else {
                // No lockout in current response → generic invalid message (do not infer countdown)
                msgDiv.innerHTML = `<div class="alert error">Invalid username and/or password</div>`;
              }
            } catch {
              msgDiv.innerHTML = '<div class="alert error">Login failed</div>';
            }
          }
        };
      })
    );
  }

  if (hash === "/register") {
    return (
      container(`<div class="card">
      <h3>Register an Account!</h3>
      <input id="firstName" placeholder="First Name" />
      <input id="lastName" placeholder="Last Name" />
      <input id="email" placeholder="Email" />
      
      <div class="field" style="position: relative;">
        <input id="password" placeholder="Password" type="password" style="padding-right: 35px;" />
        <button id="toggleRegPassword" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      
      <div class="field" style="position: relative;">
        <input id="confirmPassword" placeholder="Confirm Password" type="password" style="padding-right: 35px;" />
        <button id="toggleConfirmPassword" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      
      <div id="pwdHint" style="color:#333; font-size: 12px; margin-bottom: 10px; padding: 8px; background: #f9f9f9; border-left: 3px solid #0066cc;">
        <strong>Password Requirements:</strong>
        <ul id="pwdChecklist"></ul>
      </div>
      
      <div style="margin-top: 15px; padding: 10px; background: #f0f8ff; border-left: 3px solid #0066cc;">
        <strong>Security Questions (Select 3):</strong>
        <div id="securityQuestionsContainer" style="margin-top: 10px;"></div>
      </div>
      
      <button id="registerBtn">Register</button>
      <div id="msg"></div>
    </div>`),
      setTimeout(() => {
        // Attach password toggles
        attachPasswordToggle("password", "toggleRegPassword");
        attachPasswordToggle("confirmPassword", "toggleConfirmPassword");

        // Attach password checklist
        attachPasswordChecklist("password", "confirmPassword", "pwdHint");

        // Security Questions Logic
        const container = document.getElementById("securityQuestionsContainer");
        const selectedQuestions = {};
        const selectedAnswers = {};
        const questionInputs = {};

        const getAvailableQuestions = (excludeIndex) => {
          const selected = new Set();
          for (let i = 1; i <= 3; i++) {
            if (i !== excludeIndex && selectedQuestions[i]) {
              selected.add(selectedQuestions[i]);
            }
          }
          return SECURITY_QUESTION_POOL.filter((q) => !selected.has(q));
        };

        const renderQuestions = () => {
          // Save current answer values before re-rendering
          for (let i = 1; i <= 3; i++) {
            const answerId = `secA${i}`;
            const answerInput = document.getElementById(answerId);
            if (answerInput) {
              selectedAnswers[i] = answerInput.value;
            }
          }

          container.innerHTML = "";
          for (let i = 1; i <= 3; i++) {
            const questionId = `secQ${i}`;
            const answerId = `secA${i}`;
            const toggleId = `toggleSecA${i}`;

            const div = document.createElement("div");
            div.style.marginBottom = "15px";
            div.style.padding = "10px";
            div.style.backgroundColor = "#fff";
            div.style.border = "1px solid #ddd";
            div.style.borderRadius = "4px";

            const availableQuestions = getAvailableQuestions(i);
            const currentValue = selectedQuestions[i] || "";
            const currentAnswer = selectedAnswers[i] || "";

            div.innerHTML = `
              <label style="display: block; margin-bottom: 8px; font-weight: bold;">Question ${i}:</label>
              <select id="${questionId}" style="width: 100%; padding: 8px; margin-bottom: 8px; border: 1px solid #ccc; border-radius: 4px;">
                <option value="">-- Select a question --</option>
                ${availableQuestions
                  .map(
                    (q) =>
                      `<option value="${q}" ${
                        q === currentValue ? "selected" : ""
                      }>${q}</option>`
                  )
                  .join("")}
                ${
                  currentValue && !availableQuestions.includes(currentValue)
                    ? `<option value="${currentValue}" selected>${currentValue}</option>`
                    : ""
                }
              </select>
              <div style="position: relative;">
                <input id="${answerId}" type="password" placeholder="Your answer" value="${currentAnswer}" style="width: 100%; padding: 8px; padding-right: 35px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" />
                <button id="${toggleId}" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
              </div>
            `;

            container.appendChild(div);

            const select = document.getElementById(questionId);
            const answerInput = document.getElementById(answerId);
            const toggleBtn = document.getElementById(toggleId);

            questionInputs[i] = { select, answerInput };

            select.onchange = () => {
              selectedQuestions[i] = select.value;
              renderQuestions();
            };

            toggleBtn.onclick = (e) => {
              e.preventDefault();
              answerInput.type =
                answerInput.type === "password" ? "text" : "password";
            };
          }
        };

        renderQuestions();

        document.getElementById("registerBtn").onclick = async () => {
          const firstName = document.getElementById("firstName").value;
          const lastName = document.getElementById("lastName").value;
          const email = document.getElementById("email").value;
          const password = document.getElementById("password").value;
          const confirmPassword =
            document.getElementById("confirmPassword").value;

          // Validate passwords match
          if (password !== confirmPassword) {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Passwords do not match</div>';
            return;
          }

          // Validate all 3 questions are selected and have answers
          const securityQuestionsAnswers = [];
          for (let i = 1; i <= 3; i++) {
            const question = questionInputs[i].select.value;
            const answer = questionInputs[i].answerInput.value;

            if (!question) {
              document.getElementById(
                "msg"
              ).innerHTML = `<div class="alert error">Please select question ${i}</div>`;
              return;
            }
            if (!answer.trim()) {
              document.getElementById(
                "msg"
              ).innerHTML = `<div class="alert error">Please provide an answer for question ${i}</div>`;
              return;
            }

            securityQuestionsAnswers.push({ question, answer });
          }

          const res = await api(services.auth, "/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              firstName,
              lastName,
              email,
              password,
              securityQuestionsAnswers,
            }),
          });
          if (res.ok) {
            document.getElementById("msg").innerHTML =
              '<div class="alert success">Registered. Go to Login.</div>';
          } else {
            try {
              const err = await res.json();
              document.getElementById(
                "msg"
              ).innerHTML = `<div class="alert error">Failed: ${err.error}</div>`;
            } catch {
              document.getElementById("msg").innerHTML =
                '<div class="alert error">Registration failed</div>';
            }
          }
        };
      })
    );
  }

  if (hash === "/me/change-password") {
    if (!state.user)
      return container('<div class="alert error">Unauthorized</div>');

    return (
      container(`<div class="card">
      <h3>Change Password</h3>
      <div class="field" style="position: relative;">
        <input id="currentPassword" type="password" placeholder="Current password" style="padding-right: 35px;"/>
        <button id="toggleCurrent" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      <div class="field" style="position: relative;">
        <input id="newPassword" type="password" placeholder="New password" style="padding-right: 35px;"/>
        <button id="toggleNew" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      <div class="field" style="position: relative;">
        <input id="confirmPassword" type="password" placeholder="Confirm new password" style="padding-right: 35px;"/>
        <button id="toggleConfirm" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      <div id="cpHint" style="color:#333; font-size: 12px; margin-bottom: 10px; padding: 8px; background: #f9f9f9; border-left: 3px solid #0066cc;">
        <strong>Password Requirements:</strong>
        <ul id="cpChecklist"></ul>
      </div>
      <button id="applyChangePass">Change Password</button>
      <div id="cpMsg"></div>
    </div>
    <div class="card" style="margin-top: 20px;">
      <h3>Session Management</h3>
      <button id="revokeAllBtn">Revoke All Sessions</button>
      <div id="revokeMsg"></div>
    </div>`),
      setTimeout(() => {
        // Attach password toggles
        attachPasswordToggle("currentPassword", "toggleCurrent");
        attachPasswordToggle("newPassword", "toggleNew");
        attachPasswordToggle("confirmPassword", "toggleConfirm");

        // Attach password checklist
        attachPasswordChecklist("newPassword", "confirmPassword", "cpHint");

        document.getElementById("applyChangePass").onclick = async () => {
          const currentPassword =
            document.getElementById("currentPassword").value;
          const newPassword = document.getElementById("newPassword").value;
          const confirmPassword =
            document.getElementById("confirmPassword").value;

          if (newPassword !== confirmPassword) {
            document.getElementById("cpMsg").innerHTML =
              '<div class="alert error">New passwords do not match</div>';
            return;
          }

          const res = await api(services.auth, "/auth/change-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              currentPassword,
              newPassword,
              forceLogoutAllSessions: false,
            }),
          });

          if (res.ok) {
            document.getElementById("cpMsg").innerHTML =
              '<div class="alert success">Password changed</div>';
            document.getElementById("currentPassword").value = "";
            document.getElementById("newPassword").value = "";
            document.getElementById("confirmPassword").value = "";
          } else {
            try {
              const err = await res.json();
              let errorMsg = err.error || "Failed to change password";

              // Display time remaining if password was recently changed
              if (
                err.error === "password recently changed" &&
                err.secondsRemaining
              ) {
                const hours = Math.floor(err.secondsRemaining / 3600);
                const minutes = Math.floor((err.secondsRemaining % 3600) / 60);
                const seconds = err.secondsRemaining % 60;
                const timeStr = `${hours}h ${minutes}m ${seconds}s`;
                errorMsg = `Password was recently changed. You can change it again in ${timeStr}`;
              }

              document.getElementById(
                "cpMsg"
              ).innerHTML = `<div class="alert error">${errorMsg}</div>`;
            } catch {
              document.getElementById("cpMsg").innerHTML =
                '<div class="alert error">Failed to change password</div>';
            }
          }
        };

        document.getElementById("revokeAllBtn").onclick = async () => {
          const res = await api(services.auth, "/auth/sessions/revoke-all", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
          });

          if (res.ok) {
            document.getElementById("revokeMsg").innerHTML =
              '<div class="alert success">All sessions revoked</div>';
          } else {
            try {
              const err = await res.json();
              if (err.error === "reauth_required") {
                window.pendingAction = () => {
                  document.getElementById("revokeAllBtn").onclick();
                };
                location.hash = "#/reauthenticate";
              } else {
                document.getElementById(
                  "revokeMsg"
                ).innerHTML = `<div class="alert error">Failed: ${err.error}</div>`;
              }
            } catch {
              document.getElementById("revokeMsg").innerHTML =
                '<div class="alert error">Failed to revoke sessions</div>';
            }
          }
        };
      })
    );
  }

  if (hash === "/forgot-password") {
    return (
      container(`<div class="card">
        <h3>Forgot Password</h3>
        <div id="fpStep1">
          <input id="fpEmail" placeholder="Enter your email" />
          <button id="fpNextBtn">Next</button>
          <div id="fpMsg"></div>
        </div>
        <div id="fpStep2" style="display:none;">
          <h4>Answer Your Security Questions</h4>
          <div id="fpQuestionsContainer" style="margin-bottom: 15px;"></div>
          <div class="field" style="position: relative;">
          <input id="fpNewPassword" type="password" placeholder="New password (min 8; A-Z, a-z, 0-9, special)" style="padding-right: 35px;" />
          <button id="toggleFpNewPassword" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
          </div>
          <div class="field" style="position: relative;">
          <input id="fpConfirmPassword" type="password" placeholder="Confirm new password
          " style="padding-right: 35px;" />
          <button id="toggleFpConfirmPassword" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
          </div>
          <button id="fpResetBtn">Reset Password</button>
          <div id="fpMsg2"></div>
        </div>
      </div>`),
      setTimeout(() => {
        const validatePolicy = (pwd) =>
          /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/.test(pwd);
        const toggle = (inputId, btnId) => {
          const inp = document.getElementById(inputId);
          const btn = document.getElementById(btnId);
          if (btn)
            btn.onclick = () => {
              inp.type = inp.type === "password" ? "text" : "password";
            };
        };
        toggle("fpNewPassword", "toggleFpNewPassword");
        toggle("fpConfirmPassword", "toggleFpConfirmPassword");

        let fpEmail = null;
        let fpQuestions = null;
        const fpAnswers = {};

        document.getElementById("fpNextBtn").onclick = async () => {
          const email = document.getElementById("fpEmail").value.trim();
          if (!email) {
            document.getElementById("fpMsg").innerHTML =
              '<div class="alert error">Enter an email</div>';
            return;
          }
          const res = await api(services.auth, "/auth/forgot-password/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email }),
          });
          try {
            const data = await res.json();
            if (
              data.questions &&
              Array.isArray(data.questions) &&
              data.questions.length > 0
            ) {
              fpEmail = email;
              fpQuestions = data.questions;

              // Render questions
              const container = document.getElementById("fpQuestionsContainer");
              container.innerHTML = "";
              for (let i = 0; i < fpQuestions.length; i++) {
                const answerId = `fpAnswer${i}`;
                const toggleId = `toggleFpAnswer${i}`;

                const div = document.createElement("div");
                div.style.marginBottom = "15px";
                div.style.padding = "10px";
                div.style.backgroundColor = "#f9f9f9";
                div.style.border = "1px solid #ddd";
                div.style.borderRadius = "4px";

                div.innerHTML = `
                  <label style="display: block; margin-bottom: 8px; font-weight: bold;">Question ${
                    i + 1
                  }:</label>
                  <div style="margin-bottom: 8px; color: #333;">${
                    fpQuestions[i]
                  }</div>
                  <div style="position: relative;">
                    <input id="${answerId}" type="password" placeholder="Your answer" style="width: 100%; padding: 8px; padding-right: 35px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" />
                    <button id="${toggleId}" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
                  </div>
                `;

                container.appendChild(div);

                const answerInput = document.getElementById(answerId);
                const toggleBtn = document.getElementById(toggleId);

                toggleBtn.onclick = (e) => {
                  e.preventDefault();
                  answerInput.type =
                    answerInput.type === "password" ? "text" : "password";
                };
              }

              document.getElementById("fpStep1").style.display = "none";
              document.getElementById("fpStep2").style.display = "";
            } else {
              document.getElementById("fpMsg").innerHTML =
                '<div class="alert">If the email exists, you can reset your password.</div>';
            }
          } catch {
            document.getElementById("fpMsg").innerHTML =
              '<div class="alert error">Request failed</div>';
          }
        };

        document.getElementById("fpResetBtn").onclick = async () => {
          const newPassword = document.getElementById("fpNewPassword").value;
          const confirmPassword =
            document.getElementById("fpConfirmPassword").value;

          if (!validatePolicy(newPassword)) {
            document.getElementById("fpMsg2").innerHTML =
              '<div class="alert error">Password does not meet policy</div>';
            return;
          }
          if (newPassword !== confirmPassword) {
            document.getElementById("fpMsg2").innerHTML =
              '<div class="alert error">Passwords do not match</div>';
            return;
          }

          // Collect all answers
          const answers = [];
          for (let i = 0; i < fpQuestions.length; i++) {
            const answer = document.getElementById(`fpAnswer${i}`).value;
            if (!answer.trim()) {
              document.getElementById(
                "fpMsg2"
              ).innerHTML = `<div class="alert error">Please answer question ${
                i + 1
              }</div>`;
              return;
            }
            answers.push(answer);
          }

          const res = await api(services.auth, "/auth/forgot-password/finish", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: fpEmail, answers, newPassword }),
          });
          try {
            const data = await res.json();
            if (data.ok) {
              document.getElementById("fpMsg2").innerHTML =
                '<div class="alert success">Password reset successfully. Go to Login.</div>';
              setTimeout(() => {
                location.hash = "#/login";
              }, 2000);
            } else {
              // Display specific error message from backend
              let errorMsg =
                data.error || "Password reset failed. Please try again.";

              // Display time remaining if password was recently changed
              if (
                data.error === "Password recently changed" &&
                data.secondsRemaining
              ) {
                const hours = Math.floor(data.secondsRemaining / 3600);
                const minutes = Math.floor((data.secondsRemaining % 3600) / 60);
                const seconds = data.secondsRemaining % 60;
                const timeStr = `${hours}h ${minutes}m ${seconds}s`;
                errorMsg = `Password was recently changed. You can reset it again in ${timeStr}`;
              }

              document.getElementById(
                "fpMsg2"
              ).innerHTML = `<div class="alert error">${errorMsg}</div>`;
            }
          } catch {
            document.getElementById("fpMsg2").innerHTML =
              '<div class="alert error">Request failed</div>';
          }
        };
      })
    );
  }

  if (hash === "/reauthenticate") {
    if (!state.user)
      return container('<div class="alert error">Unauthorized</div>');
    return (
      container(`<div class="card">
        <h3>Re-authenticate</h3>
        <p>This action requires recent authentication. Please enter your password.</p>
        <input id="reauthPassword" type="password" placeholder="Password" />
        <button id="reauthBtn">Authenticate</button>
        <div id="reauthMsg"></div>
      </div>`),
      setTimeout(() => {
        document.getElementById("reauthBtn").onclick = async () => {
          const password = document.getElementById("reauthPassword").value;
          const res = await api(services.auth, "/auth/reauthenticate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password }),
          });
          if (res.ok) {
            const data = await res.json();
            setAccessToken(data.accessToken);
            document.getElementById("reauthMsg").innerHTML =
              '<div class="alert success">Authenticated. Retrying action...</div>';
            setTimeout(() => {
              if (window.pendingAction) {
                const action = window.pendingAction;
                window.pendingAction = null;
                action();
              }
              location.hash = "#/me/change-password";
            }, 1000);
          } else {
            try {
              const err = await res.json();
              document.getElementById(
                "reauthMsg"
              ).innerHTML = `<div class="alert error">Failed: ${err.error}</div>`;
            } catch {
              document.getElementById("reauthMsg").innerHTML =
                '<div class="alert error">Authentication failed</div>';
            }
          }
        };
      })
    );
  }

  if (hash === "/admin/reset-password") {
    if (state.user?.role !== "ADMIN")
      return container('<div class="alert error">Forbidden</div>');

    return (
      container(`<div class="card">
      <h3>Admin: Reset User Password</h3>
      <div class="card">
        <h4>Search User</h4>
        <input id="searchQuery" placeholder="Search by email contains..."/>
        <button id="searchUsers">Search</button>
        <div id="searchResults"></div>
      </div>
      <hr/>
      <div id="userInfo"></div>
      <div id="resetForm" style="display:none; margin-top:10px;">
        <h4>Change Password</h4>
        <div class="field" style="position: relative;">
          <input id="newPassword" type="password" placeholder="New password" style="padding-right: 35px;"/>
          <button id="toggleNewA" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
        </div>
        <div class="field" style="position: relative;">
          <input id="confirmPassword" type="password" placeholder="Confirm new password" style="padding-right: 35px;"/>
          <button id="toggleConfirmA" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
        </div>
        <div id="arHint" style="color:#333; font-size: 12px; margin-bottom: 10px; padding: 8px; background: #f9f9f9; border-left: 3px solid #0066cc;">
          <strong>Password Requirements:</strong>
          <ul id="arChecklist"></ul>
        </div>
        <button id="applyAdminReset">Reset Password</button>
        <div id="arMsg"></div>
      </div>
    </div>`),
      setTimeout(() => {
        let resolvedUserId = null;

        // Attach password toggles
        attachPasswordToggle("newPassword", "toggleNewA");
        attachPasswordToggle("confirmPassword", "toggleConfirmA");

        // Attach password checklist
        attachPasswordChecklist("newPassword", "confirmPassword", "arHint");

        const renderResults = (users) => {
          const sr = document.getElementById("searchResults");
          if (!users.length) {
            sr.innerHTML = '<div class="alert">No users found</div>';
            return;
          }

          const rows = users
            .map((u) => {
              const uid = u.id || u._id || "";
              return `<div class="card">
              <div><b>${u.email}</b> — <code>${uid}</code></div>
              <div>Role: <b>${u.role || "N/A"}</b></div>
              <button class="selectUser" data-id="${uid}" data-role="${
                u.role || ""
              }" data-email="${u.email}">Select</button>
            </div>`;
            })
            .join("");

          sr.innerHTML = rows;

          document.querySelectorAll(".selectUser").forEach((btn) => {
            btn.onclick = () => {
              const uid = btn.getAttribute("data-id");
              const role = (btn.getAttribute("data-role") || "").toUpperCase();
              const email = btn.getAttribute("data-email");
              const ui = document.getElementById("userInfo");
              const form = document.getElementById("resetForm");

              ui.innerHTML = `<div class="card">
              <div><b>ID:</b> ${uid}</div>
              <div><b>Email:</b> ${email}</div>
              <div><b>Role:</b> ${role}</div>
            </div>`;

              if (role === "ADMIN") {
                ui.innerHTML +=
                  '<div class="alert error">Forbidden: cannot reset password for ADMIN users. Ask the admin to change their own password.</div>';
                form.style.display = "none";
                resolvedUserId = null;
                return;
              }

              resolvedUserId = uid;
              form.style.display = "";
              document.getElementById("arMsg").innerHTML = "";
            };
          });
        };

        document.getElementById("searchUsers").onclick = async () => {
          const q = document.getElementById("searchQuery").value.trim();
          document.getElementById("userInfo").innerHTML = "";
          document.getElementById("resetForm").style.display = "none";

          try {
            // If query is empty, don't add the ?q= parameter → returns all users
            const url = q ? `/users?q=${encodeURIComponent(q)}` : `/users`; // fetch all
            const res = await api(services.users, url);
            if (!res.ok) throw new Error("search failed");
            const users = await res.json();
            renderResults(users);
          } catch (e) {
            document.getElementById("searchResults").innerHTML =
              '<div class="alert error">Search failed</div>';
          }
        };

        document.getElementById("applyAdminReset").onclick = async () => {
          const newPassword = document.getElementById("newPassword").value;
          const confirmPassword =
            document.getElementById("confirmPassword").value;

          if (!resolvedUserId) {
            document.getElementById("arMsg").innerHTML =
              '<div class="alert error">Select a user first</div>';
            return;
          }

          if (newPassword !== confirmPassword) {
            document.getElementById("arMsg").innerHTML =
              '<div class="alert error">New passwords do not match</div>';
            return;
          }

          const res = await api(
            services.auth,
            `/auth/admin/reset-password/${encodeURIComponent(resolvedUserId)}`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ newPassword }),
            }
          );

          if (res.ok) {
            document.getElementById("arMsg").innerHTML =
              '<div class="alert success">Password reset</div>';
            document.getElementById("newPassword").value = "";
            document.getElementById("confirmPassword").value = "";
            document.getElementById("searchQuery").value = "";
            document.getElementById("searchResults").innerHTML = "";
            document.getElementById("userInfo").innerHTML = "";
            document.getElementById("resetForm").style.display = "none";
            resolvedUserId = null;
          } else {
            try {
              const err = await res.json();
              document.getElementById(
                "arMsg"
              ).innerHTML = `<div class="alert error">Failed: ${err.error}</div>`;
            } catch {
              document.getElementById("arMsg").innerHTML =
                '<div class="alert error">Failed to reset password</div>';
            }
          }
        };
      })
    );
  }

  if (hash === "/logout") {
    await api(services.auth, "/auth/logout", { method: "POST" });
    setAccessToken(null);
    setUser(null);
    state.userActivity = null; // Clear activity on logout
    try {
      sessionStorage.removeItem("userActivity");
    } catch {}
    location.hash = "#/";
    return;
  }

  if (hash === "/courses") {
    const res = await api(services.courses, "/courses");
    if (!res.ok)
      return container(
        '<div class="alert error">Feature unavailable, please try again later.</div>'
      );
    const courses = await res.json();
    return (
      container(`<div class="card"><h3>Courses</h3>
      ${courses
        .map(
          (c) => `<div class="card">
            <a href="#/courses/${c._id}"><b>${c.code}</b> - ${c.title}</a>
            <div>${c.section ? `Section: ${c.section}` : ""}</div>
            <div>${c.description ? `Description: ${c.description}` : ""}</div>
            <div>Enrolled: ${c.enrolledCount ?? 0} / ${
            c.capacity ?? "N/A"
          } | Status: ${c.status}</div>
            <div>${
              c.professorName && c.professorEmail
                ? `Professor: ${c.professorName} (${c.professorEmail})`
                : c.professorName
                ? `Professor: ${c.professorName}`
                : c.professorEmail
                ? `Professor: ${c.professorEmail}`
                : ""
            }</div>
            ${
              state.user?.role === "STUDENT"
                ? `<button data-id="${c._id}" class="enroll">Enroll</button>`
                : ""
            }
          </div>`
        )
        .join("")}
    </div>`),
      setTimeout(() => {
        document.querySelectorAll(".enroll").forEach(
          (btn) =>
            (btn.onclick = async (e) => {
              const id = e.target.getAttribute("data-id");
              const res = await api(services.courses, `/courses/${id}/enroll`, {
                method: "POST",
              });
              if (res.ok) {
                alert("Enrolled");
                location.reload(); // Refresh to see updated course status
              } else {
                try {
                  const err = await res.json();
                  alert(`Enroll failed: ${err.error || res.status}`);
                } catch {
                  alert("Enroll failed");
                }
              }
            })
        );
      })
    );
  }

  if (hash === "/me/enrollments") {
    const res = await api(services.courses, "/me/enrollments");
    if (!res.ok)
      return container(
        '<div class="alert error">Feature unavailable, please try again later.</div>'
      );
    const items = await res.json();
    const courseMap = await getCourseMap();
    const enrolledCourses = items.filter((i) => i.status === "ENROLLED");
    return (
      container(`<div class="card"><h3>My Courses</h3>
        ${
          enrolledCourses.length
            ? enrolledCourses
                .map((i) => {
                  const c = courseMap[i.courseId];
                  const label = c
                    ? `${c.code} — ${c.title}`
                    : `Course: ${i.courseId}`;
                  const canDrop = c?.droppingAllowed;
                  return `<div class="card">
              <div>${label}</div>
              <div>Status: ${i.status}</div>
              ${
                canDrop
                  ? `<button class="dropCourse" data-id="${i.courseId}">Drop Course</button>`
                  : '<div style="color: #999;">Dropping not allowed</div>'
              }
            </div>`;
                })
                .join("")
            : '<div class="alert">Not enrolled in any courses</div>'
        }
      </div>`),
      setTimeout(() => {
        document.querySelectorAll(".dropCourse").forEach(
          (btn) =>
            (btn.onclick = async (e) => {
              const courseId = e.target.getAttribute("data-id");
              if (confirm("Are you sure you want to drop this course?")) {
                const r = await api(
                  services.courses,
                  `/courses/${courseId}/enroll`,
                  {
                    method: "DELETE",
                  }
                );
                if (r.ok) {
                  alert("Course dropped successfully");
                  location.reload();
                } else {
                  alert("Failed to drop course");
                }
              }
            })
        );
      })
    );
  }

  if (hash === "/me/grades") {
    const gradesRes = await api(services.grades, "/me/grades");
    if (!gradesRes.ok)
      return container(
        '<div class="alert error">Feature unavailable, please try again later.</div>'
      );
    const grades = await gradesRes.json();
    return container(`<div class="card"><h3>My Grades</h3>
      ${
        grades.length
          ? grades
              .map((g) => {
                const label = g.courseCode
                  ? `${g.courseCode}`
                  : `Course ID: ${g.courseId}`;
                return `<div class="card">${label} — Grade: ${g.value}</div>`;
              })
              .join("")
          : '<div class="alert">No grades assigned yet</div>'
      }
    </div>`);
  }

  if (hash === "/faculty/courses") {
    if (state.user?.role !== "TEACHER")
      return container('<div class="alert error">Forbidden</div>');
    return (
      container(`<div class="card">
      <h3>Create Courses</h3>
      <input id="code" placeholder="Course Code"/>
      <input id="section" placeholder="Section"/>
      <input id="title" placeholder="Title"/>
      <input id="description" placeholder="Description"/>
      <input id="capacity" placeholder="Capacity" type="number"/>
      <select id="status"><option value="OPEN">OPEN</option><option value="CLOSED">CLOSED</option></select>
      <div style="margin-top: 10px; padding: 10px; background: #f0f0f0; border-radius: 4px;">
        <div><strong>Professor Email:</strong> ${
          state.user?.email || "N/A"
        }</div>
        <div><strong>Professor Name:</strong> ${
          state.user ? `${state.user.firstName} ${state.user.lastName}` : "N/A"
        }</div>
      </div>
      <button id="createCourse">Create</button>
      <div id="msg"></div>
    </div>`),
      setTimeout(() => {
        document.getElementById("createCourse").onclick = async () => {
          const code = document.getElementById("code").value.trim();
          const section = document.getElementById("section").value.trim();
          const title = document.getElementById("title").value.trim();
          const description = document
            .getElementById("description")
            .value.trim();
          const capacityInput = document
            .getElementById("capacity")
            .value.trim();
          const capacityNum = Number(capacityInput);

          // Validate all fields are filled
          if (code === "") {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Course code is required</div>';
            return;
          }
          if (section === "") {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Section is required</div>';
            return;
          }
          if (title === "") {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Title is required</div>';
            return;
          }
          if (description === "") {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Description is required</div>';
            return;
          }

          // Validate capacity
          if (capacityInput === "") {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Capacity is required</div>';
            return;
          }
          if (isNaN(capacityNum)) {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Capacity must be a number</div>';
            return;
          }
          if (capacityNum <= 0) {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Capacity must be positive</div>';
            return;
          }

          const payload = {
            code: code,
            section: section,
            title: title,
            description: description,
            capacity: capacityNum,
            status: document.getElementById("status").value,
            professorEmail: state.user?.email,
            professorName: state.user
              ? `${state.user.firstName} ${state.user.lastName}`
              : undefined,
          };
          const res = await api(services.courses, "/courses", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          document.getElementById("msg").innerHTML = res.ok
            ? '<div class="alert success">Course Successfully Created</div>'
            : '<div class="alert error">Failed</div>';
        };
      })
    );
  }

  // Removed faculty/grades route in favor of per-course grading

  if (hash === "/admin/users") {
    if (state.user?.role !== "ADMIN")
      return container('<div class="alert error">Forbidden</div>');
    return (
      container(`
  <div class="card">
    <h3>Edit Users Role</h3>
    <input id="searchQ" placeholder="Search email contains..."/>
    <button id="searchBtn">Search</button>
    <div id="searchMsg"></div>
    <div id="results"></div>
  </div>
  <div class="card" style="margin-top: 16px;">
      <h3>Create User (Admin/Teacher/Student)</h3>
      <input id="firstName" placeholder="First Name"/>
      <input id="lastName" placeholder="Last Name"/>
      <input id="email" placeholder="Email"/>

      <div class="field" style="position: relative;">
        <input id="adminPassword" placeholder="Password (min 8; A-Z, a-z, 0-9, special)" type="password" style="padding-right: 35px;" />
        <button id="toggleAdminPwd" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      <div class="field" style="position: relative;">
        <input id="adminConfirmPassword" placeholder="Confirm Password" type="password" style="padding-right: 35px;" />
        <button id="toggleAdminConfirm" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
      </div>
      <div id="adminPwdHint" style="color:#333; font-size: 12px; margin-bottom: 10px; padding: 8px; background: #f9f9f9; border-left: 3px solid #0066cc;">
        <strong>Password Requirements:</strong>
        <ul id="adminPwdChecklist"></ul>
      </div>

      <div style="margin-top: 15px; padding: 10px; background: #f0f8ff; border-left: 3px solid #0066cc;">
        <strong>Security Questions (Select 3):</strong>
        <div id="adminSecurityQuestionsContainer" style="margin-top: 10px;"></div>
      </div>

      <label for="role" style="font-weight: bold; display: block; margin-top: 10px;">Role</label>
      <select id="role"><option>ADMIN</option><option>TEACHER</option><option>STUDENT</option></select>
      <button id="createUser">Create</button>
      <div id="msg"></div>
    </div>
  `),
      setTimeout(() => {
        // Toggles for admin password/confirm
        attachPasswordToggle("adminPassword", "toggleAdminPwd");
        attachPasswordToggle("adminConfirmPassword", "toggleAdminConfirm");
        // Checklist for admin create-user
        attachPasswordChecklist(
          "adminPassword",
          "adminConfirmPassword",
          "adminPwdHint"
        );

        // Render 3 security questions with duplicate prevention
        const containerQ = document.getElementById(
          "adminSecurityQuestionsContainer"
        );
        const selectedQuestions = {};
        const selectedAnswers = {};
        const questionInputs = {};

        const getAvailableQuestions = (excludeIndex) => {
          const selected = new Set();
          for (let i = 1; i <= 3; i++) {
            if (i !== excludeIndex && selectedQuestions[i]) {
              selected.add(selectedQuestions[i]);
            }
          }
          return SECURITY_QUESTION_POOL.filter((q) => !selected.has(q));
        };

        const renderQuestions = () => {
          // Preserve current answers
          for (let i = 1; i <= 3; i++) {
            const answerId = `adminSecA${i}`;
            const answerInput = document.getElementById(answerId);
            if (answerInput) selectedAnswers[i] = answerInput.value;
          }

          containerQ.innerHTML = "";
          for (let i = 1; i <= 3; i++) {
            const questionId = `adminSecQ${i}`;
            const answerId = `adminSecA${i}`;
            const toggleId = `toggleAdminSecA${i}`;

            const div = document.createElement("div");
            div.style.marginBottom = "15px";
            div.style.padding = "10px";
            div.style.backgroundColor = "#fff";
            div.style.border = "1px solid #ddd";
            div.style.borderRadius = "4px";

            const availableQuestions = getAvailableQuestions(i);
            const currentValue = selectedQuestions[i] || "";
            const currentAnswer = selectedAnswers[i] || "";

            div.innerHTML = `
              <label style="display: block; margin-bottom: 8px; font-weight: bold;">Question ${i}:</label>
              <select id="${questionId}" style="width: 100%; padding: 8px; margin-bottom: 8px; border: 1px solid #ccc; border-radius: 4px;">
                <option value="">-- Select a question --</option>
                ${availableQuestions
                  .map(
                    (q) =>
                      `<option value="${q}" ${
                        q === currentValue ? "selected" : ""
                      }>${q}</option>`
                  )
                  .join("")}
                ${
                  currentValue && !availableQuestions.includes(currentValue)
                    ? `<option value="${currentValue}" selected>${currentValue}</option>`
                    : ""
                }
              </select>
              <div style="position: relative;">
                <input id="${answerId}" type="password" placeholder="Your answer" value="${currentAnswer}" style="width: 100%; padding: 8px; padding-right: 35px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" />
                <button id="${toggleId}" type="button" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; padding: 0;">👁</button>
              </div>
            `;

            containerQ.appendChild(div);

            const select = document.getElementById(questionId);
            const answerInput = document.getElementById(answerId);
            const toggleBtn = document.getElementById(toggleId);

            questionInputs[i] = { select, answerInput };

            select.onchange = () => {
              selectedQuestions[i] = select.value;
              renderQuestions();
            };

            toggleBtn.onclick = (e) => {
              e.preventDefault();
              answerInput.type =
                answerInput.type === "password" ? "text" : "password";
            };
          }
        };

        renderQuestions();

        document.getElementById("createUser").onclick = async () => {
          const firstName = document.getElementById("firstName").value.trim();
          const lastName = document.getElementById("lastName").value.trim();
          const email = document.getElementById("email").value.trim();
          const password = document.getElementById("adminPassword").value;
          const confirmPassword = document.getElementById(
            "adminConfirmPassword"
          ).value;
          const role = document.getElementById("role").value;

          if (
            !firstName ||
            !lastName ||
            !email ||
            !password ||
            !confirmPassword
          ) {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">All fields required</div>';
            return;
          }

          if (password !== confirmPassword) {
            document.getElementById("msg").innerHTML =
              '<div class="alert error">Passwords do not match</div>';
            return;
          }

          // Validate 3 questions selected and with answers
          const securityQuestionsAnswers = [];
          for (let i = 1; i <= 3; i++) {
            const question = questionInputs[i].select.value;
            const answer = questionInputs[i].answerInput.value;
            if (!question) {
              document.getElementById(
                "msg"
              ).innerHTML = `<div class="alert error">Please select question ${i}</div>`;
              return;
            }
            if (!answer.trim()) {
              document.getElementById(
                "msg"
              ).innerHTML = `<div class="alert error">Please provide an answer for question ${i}</div>`;
              return;
            }
            securityQuestionsAnswers.push({ question, answer });
          }

          const payload = {
            firstName,
            lastName,
            email,
            password,
            role,
            securityQuestionsAnswers,
          };
          const res = await api(services.auth, "/auth/users", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });

          if (res.ok) {
            const data = await res.json();
            document.getElementById(
              "msg"
            ).innerHTML = `<div class="alert success">Created user: ${data.firstName} ${data.lastName} (${data.role})</div>`;
            document.getElementById("firstName").value = "";
            document.getElementById("lastName").value = "";
            document.getElementById("email").value = "";
            document.getElementById("adminPassword").value = "";
            document.getElementById("adminConfirmPassword").value = "";
            renderQuestions();
          } else {
            try {
              const err = await res.json();
              document.getElementById(
                "msg"
              ).innerHTML = `<div class="alert error">Failed: ${err.error}</div>`;
            } catch {
              document.getElementById("msg").innerHTML =
                '<div class="alert error">Failed to create user</div>';
            }
          }
        };

        document.getElementById("searchBtn").onclick = async () => {
          const q = document.getElementById("searchQ").value;
          const url = q ? `/users?q=${encodeURIComponent(q)}` : "/users";
          const res = await api(services.users, url);
          if (!res.ok)
            return (document.getElementById("searchMsg").innerHTML =
              '<div class="alert error">Search failed</div>');
          const users = await res.json();
          if (!users.length) {
            document.getElementById("results").innerHTML =
              '<div class="alert">No users found</div>';
            return;
          }
          const rows = users
            .map(
              (u) => `
          <div class="card">
            <div><b>${u.email}</b> — <code>${u.id}</code></div>
            <div>Current role: <b id="role_display_${u.id}">${u.role}</b></div>
            <div>
              <select id="role_${u.id}">
                <option ${u.role === "ADMIN" ? "selected" : ""}>ADMIN</option>
                <option ${
                  u.role === "TEACHER" ? "selected" : ""
                }>TEACHER</option>
                <option ${
                  u.role === "STUDENT" ? "selected" : ""
                }>STUDENT</option>
              </select>
              <button data-id="${u.id}" class="applyRole">Apply</button>
              <span id="status_${u.id}"></span>
            </div>
          </div>
        `
            )
            .join("");
          document.getElementById("results").innerHTML = rows;

          document.querySelectorAll(".applyRole").forEach((btn) => {
            btn.onclick = async (e) => {
              const buttonEl = e.currentTarget;
              const id = buttonEl.getAttribute("data-id");
              const roleSel = document.getElementById(`role_${id}`);
              const role = roleSel.value;
              const statusEl = document.getElementById(`status_${id}`);
              const roleDisplayEl = document.getElementById(
                `role_display_${id}`
              );

              // Disable while saving
              buttonEl.disabled = true;
              statusEl.innerHTML = '<span class="alert">Saving...</span>';

              const r = await api(
                services.auth,
                `/auth/users/${encodeURIComponent(id)}/role`,
                {
                  method: "PATCH",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ role }),
                }
              );

              if (r.ok) {
                // Update displayed role immediately
                if (roleDisplayEl) roleDisplayEl.textContent = role;
                statusEl.innerHTML =
                  '<span class="alert success">Updated</span>';
              } else {
                statusEl.innerHTML = '<span class="alert error">Failed</span>';
              }

              // Auto-clear status after 2s and re-enable button
              setTimeout(() => {
                statusEl.innerHTML = "";
              }, 2000);
              buttonEl.disabled = false;
            };
          });
        };
      })
    );
  }

  if (hash.startsWith("/admin/audit")) {
    if (state.user?.role !== "ADMIN")
      return container('<div class="alert error">Forbidden</div>');

    // Parse the view param from the normalized hash (without leading #)
    const qIndex = hash.indexOf("?");
    const queryStr = qIndex >= 0 ? hash.slice(qIndex + 1) : "";
    const params = new URLSearchParams(queryStr);
    const view = params.get("view") || "actions";

    const basePath =
      view === "security"
        ? "/audit/security"
        : view === "all"
        ? "/audit"
        : "/audit/actions";
    const url = `${basePath}`;

    const res = await api(services.audit, url);
    if (!res.ok)
      return container(
        '<div class="alert error">Feature unavailable, please try again later.</div>'
      );
    const items = await res.json();

    const controls = `
      <div style="margin-bottom:10px;">
        <label>View: </label>
        <select id="auditView">
          <option value="actions" ${
            view === "actions" ? "selected" : ""
          }>Action Audit</option>
          <option value="security" ${
            view === "security" ? "selected" : ""
          }>Security Audit</option>
          <option value="all" ${view === "all" ? "selected" : ""}>All</option>
        </select>
      </div>`;

    return (
      container(`<div class="card"><h3>Audit Logs</h3>
        ${controls}
        ${
          items.length
            ? items
                .map(
                  (i) => `<div class="card">
            <div><b>${i.action}</b> — ${i.status} — <span style="color:#666;">${
                    i.severity
                  }</span></div>
            <div>${new Date(i.timestamp).toLocaleString()} — ${i.actorRole} (${
                    i.actorId
                  })</div>
            <div>${i.entityType}:${i.entityId}</div>
          </div>`
                )
                .join("")
            : '<div class="alert">No logs</div>'
        }
      </div>`),
      setTimeout(() => {
        const viewSel = document.getElementById("auditView");
        if (viewSel) {
          viewSel.onchange = () => {
            const v = viewSel.value;
            const newHash = `#/admin/audit?view=${encodeURIComponent(v)}`;
            if (location.hash !== newHash) {
              location.hash = newHash; // triggers hashchange -> onRoute()
            } else {
              // Force rerender when hash does not change (same selection)
              window.dispatchEvent(new HashChangeEvent("hashchange"));
            }
          };
        }
      })
    );
  }

  // Course management view (click from Courses list)
  const courseMatch = hash.match(/^\/courses\/([^\/]+)$/);
  if (courseMatch) {
    const courseId = courseMatch[1];
    const courseRes = await api(services.courses, "/courses");
    if (!courseRes.ok)
      return container(
        '<div class="alert error">Feature unavailable, please try again later.</div>'
      );
    const allCourses = await courseRes.json();
    const course = allCourses.find((c) => c._id === courseId);
    if (!course)
      return container(
        '<div class="alert error">Course not found or not visible</div>'
      );

    const rosterRes = await api(
      services.courses,
      `/courses/${courseId}/enrollments`
    );
    const rosterOk = rosterRes.ok;
    const roster = rosterOk ? await rosterRes.json() : [];

    const gradesOptions = [
      "",
      "4.0",
      "3.5",
      "3.0",
      "2.5",
      "2.0",
      "1.5",
      "1.0",
      "0.0",
      "W",
    ];

    return (
      container(`<div class="card">
        <h3>${course.code} - ${course.title}</h3>
        <div>${course.section ? `Section: ${course.section}` : ""}</div>
        <div>${
          course.description ? `Description: ${course.description}` : ""
        }</div>
        <div>Enrolled: <span id="enrolledCount">${
          rosterOk ? roster.length : course.enrolledCount ?? 0
        }</span> / <span id="capVal">${course.capacity ?? "N/A"}</span></div>
        <div>Status: ${course.status}</div>
        <div>${
          course.professorName && course.professorEmail
            ? `Professor: ${course.professorName} (${course.professorEmail})`
            : course.professorName
            ? `Professor: ${course.professorName}`
            : course.professorEmail
            ? `Professor: ${course.professorEmail}`
            : ""
        }</div>

        ${
          state.user?.role === "TEACHER" && rosterOk
            ? `
        <div class="card">
          <h4>Manage Status</h4>
          <select id="statusSelect">
            <option value="OPEN" ${
              course.status === "OPEN" ? "selected" : ""
            }>OPEN</option>
            <option value="CLOSED" ${
              course.status === "CLOSED" ? "selected" : ""
            }>CLOSED</option>
          </select>
          <button id="applyStatus">Apply</button>
          <div id="statusMsg"></div>
        </div>
        <div class="card">
          <h4>Dropping Policy</h4>
          <label>
            <input type="checkbox" id="droppingAllowed" ${
              course.droppingAllowed ? "checked" : ""
            } />
            Allow students to drop this course
          </label>
          <button id="applyDropping">Apply</button>
          <div id="droppingMsg"></div>
        </div>
        <div class="card">
          <h4>Manage Capacity</h4>
          <input id="newCapacity" type="number" placeholder="New capacity"/>
          <button id="applyCapacity">Apply</button>
          <div id="capMsg"></div>
        </div>
        <div class="card">
          <h4>Enrolled Students</h4>
          ${
            roster.length
              ? roster
                  .map(
                    (r) => `
            <div class="card">
              <div>Student: <code>${r.studentId}</code></div>
              <div>Grade: <b id="grade_display_${r.studentId}">--</b></div>
              <div>
                <select id="grade_${r.studentId}">
                  ${gradesOptions
                    .map((g) => `<option value="${g}">${g || "--"}</option>`)
                    .join("")}
                </select>
                <button class="applyGrade" data-student="${
                  r.studentId
                }">Set Grade</button>
                <button class="removeStudent" data-student="${
                  r.studentId
                }">Remove</button>
              </div>
            </div>
          `
                  )
                  .join("")
              : '<div class="alert">No enrolled students</div>'
          }
          <div id="rosterMsg"></div>
        </div>`
            : ""
        }
      </div>`),
      setTimeout(() => {
        const statusBtn = document.getElementById("applyStatus");
        if (statusBtn)
          statusBtn.onclick = async () => {
            const newStatus = document.getElementById("statusSelect").value;
            const r = await api(services.courses, `/courses/${courseId}`, {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ status: newStatus }),
            });
            document.getElementById("statusMsg").innerHTML = r.ok
              ? '<div class="alert success">Status Updated</div>'
              : '<div class="alert error">Failed</div>';
            if (r.ok) {
              try {
                const updated = await r.json();
                // Update the displayed status
                document.querySelector(
                  "div:nth-child(4)"
                ).innerText = `Status: ${updated.status}`;
              } catch {}
            }
          };
        const droppingBtn = document.getElementById("applyDropping");
        if (droppingBtn)
          droppingBtn.onclick = async () => {
            const droppingAllowed =
              document.getElementById("droppingAllowed").checked;
            const r = await api(
              services.courses,
              `/courses/${courseId}/dropping`,
              {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ droppingAllowed }),
              }
            );
            document.getElementById("droppingMsg").innerHTML = r.ok
              ? '<div class="alert success">Dropping policy updated</div>'
              : '<div class="alert error">Failed</div>';
          };
        const capBtn = document.getElementById("applyCapacity");
        if (capBtn)
          capBtn.onclick = async () => {
            const cap = Number(document.getElementById("newCapacity").value);
            const r = await api(
              services.courses,
              `/courses/${courseId}/capacity`,
              {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ capacity: cap }),
              }
            );
            document.getElementById("capMsg").innerHTML = r.ok
              ? '<div class="alert success">Updated</div>'
              : '<div class="alert error">Failed</div>';
            if (r.ok) {
              try {
                const updated = await r.json();
                document.getElementById("capVal").innerText = updated.capacity;
              } catch {}
            }
          };
        document.querySelectorAll(".removeStudent").forEach(
          (btn) =>
            (btn.onclick = async (e) => {
              const sid = e.target.getAttribute("data-student");
              const r = await api(
                services.courses,
                `/courses/${courseId}/students/${sid}`,
                { method: "DELETE" }
              );
              document.getElementById("rosterMsg").innerHTML = r.ok
                ? '<div class="alert success">Removed</div>'
                : '<div class="alert error">Failed</div>';
              if (r.ok) location.reload();
            })
        );
        document.querySelectorAll(".applyGrade").forEach(
          (btn) =>
            (btn.onclick = async (e) => {
              const sid = e.target.getAttribute("data-student");
              const gradeValue = document.getElementById(`grade_${sid}`).value;
              if (!gradeValue) {
                document.getElementById("rosterMsg").innerHTML =
                  '<div class="alert error">Please select a grade</div>';
                return;
              }
              const r = await api(services.grades, `/grades`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  studentId: sid,
                  courseId: courseId,
                  courseCode: course.code,
                  value: gradeValue,
                }),
              });
              document.getElementById("rosterMsg").innerHTML = r.ok
                ? '<div class="alert success">Grade Updated</div>'
                : '<div class="alert error">Failed</div>';
              if (r.ok) {
                document.getElementById(`grade_display_${sid}`).innerText =
                  gradeValue;
              }
            })
        );
      })
    );
  }

  container('<div class="alert error">Not Found</div>');
}

window.addEventListener("hashchange", onRoute);
function render() {
  onRoute();
}
// Attempt to restore auth on load (render only once inside initAuth)
initAuth();
