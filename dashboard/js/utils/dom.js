// dashboard/js/utils/dom.js
// basic DOM helpers so we don't have to write document.querySelector everywhere

const $ = selector => document.querySelector(selector);
const $$ = selector => document.querySelectorAll(selector);

// create an element with attributes and children
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

  // append children (can be strings or nodes)
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

// clear all children from an element
function empty(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

// simple HTML sanitizer to prevent XSS in the dashboard itself
function escapeHTML(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

window.DOM = { $, $$, h, empty, escapeHTML };
