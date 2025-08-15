(function(){
  window.authFetch = function(input, init={}) {
    const token = localStorage.getItem('lotus_token');
    const headers = new Headers(init.headers || {});
    if (token) headers.set('Authorization', `Bearer ${token}`);
    headers.set('Cache-Control','no-store');
    return fetch(input, { ...init, headers });
  };
  window.getMyShops = function(){
    try { return JSON.parse(localStorage.getItem('lotus_shops') || '[]'); }
    catch { return []; }
  };
  window.requireLogin = function(){
    if (!localStorage.getItem('lotus_token')) location.href='/login.html';
  };
})();
