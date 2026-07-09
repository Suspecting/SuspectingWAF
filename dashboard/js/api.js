class APIClient {
  constructor(baseUrl = '/api/v1') {
    this.baseUrl = baseUrl;
  }

  getToken() {
    return localStorage.getItem('swaf_token');
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const token = this.getToken();
    
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
      ...options,
      headers
    };

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    try {
      const res = await fetch(url, config);
      if (res.status === 401 && endpoint !== '/auth/login') {
        window.Auth.logout();
        return;
      }

      const data = await res.json().catch(() => ({}));
      
      if (!res.ok) {
        throw new Error(data.error || `API error: ${res.status}`);
      }

      return data;
    } catch (err) {
      console.error(`API Request failed for ${endpoint}:`, err);
      throw err;
    }
  }

  get(endpoint, params = null) {
    let url = endpoint;
    if (params) {
      const query = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null && v !== '') {
          query.append(k, v);
        }
      }
      const q = query.toString();
      if (q) url += `?${q}`;
    }
    return this.request(url, { method: 'GET' });
  }

  post(endpoint, body) {
    return this.request(endpoint, { method: 'POST', body });
  }

  put(endpoint, body) {
    return this.request(endpoint, { method: 'PUT', body });
  }

  delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }
}

window.API = new APIClient();
