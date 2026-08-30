async function authRequest(url, options = {}) {
  const response = await fetch(url, { ...options, credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

async function signup(email, password) {
  return authRequest('/api/auth/signup', { method: 'POST', body: JSON.stringify({ email, password }) });
}

async function login(email, password) {
  return authRequest('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
}

async function currentUser() {
  return authRequest('/api/auth/me');
}

async function logout() {
  return authRequest('/api/auth/logout', { method: 'POST' });
}

async function requireAuth({ premium = false } = {}) {
  try {
    const data = await currentUser();
    if (premium && !data.user.premium) {
      window.location.href = 'premium.html';
      return null;
    }
    return data.user;
  } catch {
    window.location.href = 'login.html';
    return null;
  }
}

window.View49Auth = { signup, login, currentUser, logout, requireAuth };
