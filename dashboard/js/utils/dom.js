const $ = selector => document.querySelector(selector);
const $$ = selector => document.querySelectorAll(selector);
function h(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  
  for (const [key, val] of Object.entries(attrs)) {
    if (key === 'className') {
      el.className = val;
    } else if (key === 'dataset') {
      for (const [dKey, dVal] of Object.entries(val)) {
        el.dataset[dKey] = dVal;
      }
    } else if (key.startsWith('on') && typeof val === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), val);
    } else if (val !== null && val !== undefined) {
      el.setAttribute(key, val);
    }
  }
  const append = (child) => {
    if (Array.isArray(child)) {
      child.forEach(append);
    } else if (child instanceof Node) {
      el.appendChild(child);
    } else if (child !== null && child !== undefined) {
      el.appendChild(document.createTextNode(String(child)));
    }
  };

  if (Array.isArray(children)) {
    children.forEach(append);
  } else {
    append(children);
  }
  return el;
}
function empty(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}
function escapeHTML(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

window.DOM = { $, $$, h, empty, escapeHTML };
