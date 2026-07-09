// dashboard/js/components/modal.js
// simple modal manager

const Modal = {
  overlay: null,
  content: null,
  
  init() {
    this.overlay = document.getElementById('modalOverlay');
    this.content = document.getElementById('modalContent');
    
    if (this.overlay) {
      // close on overlay click (if event target is the overlay itself)
      this.overlay.addEventListener('click', (e) => {
        if (e.target === this.overlay) this.close();
      });
    }
  },

  /**
   * Show a modal
   * @param {string} title Modal title
   * @param {HTMLElement|string} bodyContent DOM element or HTML string
   * @param {HTMLElement|string} footerContent Optional footer buttons
   */
  show(title, bodyContent, footerContent = '') {
    if (!this.overlay) this.init();
    if (!this.overlay) return;

    const { h } = DOM;

    // header
    const closeBtn = h('div', { className: 'modal-close', title: 'Close', onclick: () => this.close() }, '✕');
    const header = h('div', { className: 'modal-header' }, [
      h('div', { className: 'modal-title' }, title),
      closeBtn
    ]);

    // body
    const body = h('div', { className: 'modal-body' });
    if (typeof bodyContent === 'string') {
      body.innerHTML = bodyContent;
    } else {
      body.appendChild(bodyContent);
    }

    // footer
    let footer = null;
    if (footerContent) {
      footer = h('div', { className: 'modal-footer' });
      if (typeof footerContent === 'string') {
        footer.innerHTML = footerContent;
      } else if (Array.isArray(footerContent)) {
        footerContent.forEach(el => footer.appendChild(el));
      } else {
        footer.appendChild(footerContent);
      }
    }

    DOM.empty(this.content);
    this.content.appendChild(header);
    this.content.appendChild(body);
    if (footer) this.content.appendChild(footer);

    this.overlay.classList.add('active');
    
    // auto focus first input if any
    setTimeout(() => {
      const firstInput = this.content.querySelector('input:not([type="hidden"]):not(:disabled), select:not(:disabled), textarea:not(:disabled)');
      if (firstInput) firstInput.focus();
    }, 100);
  },

  /**
   * Convenience method to show a confirmation dialog
   */
  confirm(title, message, confirmText, onConfirm, isDanger = false) {
    const { h } = DOM;
    
    const body = h('p', {}, message);
    
    const cancelBtn = h('button', { 
      className: 'btn btn-secondary', 
      onclick: () => this.close() 
    }, 'Cancel');
    
    const confirmBtn = h('button', { 
      className: `btn ${isDanger ? 'btn-danger' : 'btn-primary'}`,
      onclick: () => {
        onConfirm();
        this.close();
      }
    }, confirmText);

    this.show(title, body, [cancelBtn, confirmBtn]);
  },

  close() {
    if (this.overlay) {
      this.overlay.classList.remove('active');
      // optional: clear content after animation finishes
      setTimeout(() => {
        if (!this.overlay.classList.contains('active')) {
          DOM.empty(this.content);
        }
      }, 300);
    }
  }
};

window.Modal = Modal;
