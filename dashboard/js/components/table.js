// dashboard/js/components/table.js
// simple data table builder

class DataTable {
  constructor({ columns, data, emptyText = 'No data available', onRowClick = null }) {
    this.columns = columns; // array of { key, label, render(val, row) }
    this.data = data || [];
    this.emptyText = emptyText;
    this.onRowClick = onRowClick;
  }

  render() {
    const { h } = DOM;

    if (!this.data || this.data.length === 0) {
      return h('div', { className: 'table-empty' }, [
        h('div', { className: 'empty-icon' }, '📄'),
        h('div', {}, this.emptyText)
      ]);
    }

    // thead
    const thead = h('thead', {}, [
      h('tr', {}, this.columns.map(col => 
        h('th', {}, col.label)
      ))
    ]);

    // tbody
    const tbody = h('tbody', {}, this.data.map((row, idx) => {
      const tr = h('tr', { 
        style: this.onRowClick ? 'cursor: pointer' : '' 
      }, this.columns.map(col => {
        const val = row[col.key];
        const content = col.render ? col.render(val, row) : (val !== null && val !== undefined ? String(val) : '');
        
        const td = h('td');
        if (typeof content === 'string') {
          td.innerHTML = content; // allow HTML from renderers (be careful with XSS!)
        } else if (content instanceof Node) {
          td.appendChild(content);
        }
        return td;
      }));

      if (this.onRowClick) {
        tr.addEventListener('click', (e) => {
          // ignore clicks on buttons/links inside the row
          if (e.target.tagName === 'BUTTON' || e.target.tagName === 'A' || e.target.closest('button')) {
            return;
          }
          this.onRowClick(row, idx);
        });
      }

      return tr;
    }));

    return h('div', { style: 'overflow-x: auto' }, [
      h('table', { className: 'data-table' }, [thead, tbody])
    ]);
  }
}

window.DataTable = DataTable;
