// dashboard/js/auth.js
// auth state management

const Auth = {
  getToken() {
    return localStorage.getItem('swaf_token');
  },
  
  getUser() {
    try {
      return JSON.parse(localStorage.getItem('swaf_user') || 'null');
    } catch {
      return null;
    }
  },

  isLoggedIn() {
    return !!this.getToken();
  },

  logout() {
    localStorage.removeItem('swaf_token');
    localStorage.removeItem('swaf_user');
    window.location.href = '/dashboard/login.html';
  },

  async check() {
    if (!this.isLoggedIn()) {
      this.logout();
      return false;
    }

    try {
      const res = await window.API.get('/auth/me');
      localStorage.setItem('swaf_user', JSON.stringify(res.user));
      return true;
    } catch (err) {
      this.logout();
      return false;
    }
  }
};

window.Auth = Auth;
