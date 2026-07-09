const Modal = {
  overlay: null,
  content: null,
  
  init() {
    this.overlay = document.getElementById('modalOverlay');
    this.content = document.getElementById('modalContent');
    
    if (this.overlay) {
      this.overlay.addEventListener('click', (e) => {
        if (e.target === this.overlay) this.close();
      });
    }
  },

  
  show(title, bodyContent, footerContent = '') {
    if (!this.overlay) this.init();
    if (!this.overlay) return;

    const { h } = DOM;
    const closeBtn = h('div', { className: 'modal-close', title: 'Close', onclick: () => this.close() }, '✕');
    const header = h('div', { className: 'modal-header' }, [
      h('div', { className: 'modal-title' }, title),
      closeBtn
    ]);
    const body = h('div', { className: 'modal-body' });
    if (typeof bodyContent === 'string') {
      body.innerHTML = bodyContent;
    } else {
      body.appendChild(bodyContent);
    }
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
    setTimeout(() => {
      const firstInput = this.content.querySelector('input:not([type="hidden"]):not(:disabled), select:not(:disabled), textarea:not(:disabled)');
      if (firstInput) firstInput.focus();
    }, 100);
  },

  
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
      setTimeout(() => {
        if (!this.overlay.classList.contains('active')) {
          DOM.empty(this.content);
        }
      }, 300);
    }
  }
};

window.Modal = Modal;
