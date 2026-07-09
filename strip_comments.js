const fs = require('fs');
const path = require('path');

function processDir(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      processDir(fullPath);
    } else {
      if (fullPath.endsWith('.js') || fullPath.endsWith('.css') || fullPath.endsWith('.html')) {
        let content = fs.readFileSync(fullPath, 'utf8');
        
        // Remove lines that start with // (ignoring leading whitespace)
        content = content.replace(/^\s*\/\/.*(\r?\n|$)/gm, '');
        
        // Remove block comments that are on their own lines or inline
        content = content.replace(/\/\*[\s\S]*?\*\//g, '');

        // HTML comments
        if (fullPath.endsWith('.html')) {
            content = content.replace(/<!--[\s\S]*?-->/g, '');
        }
        
        // Squeeze multiple empty lines into max one empty line
        content = content.replace(/(\r?\n){3,}/g, '\n\n');
        
        // trim leading/trailing newlines
        content = content.trim() + '\n';
        
        fs.writeFileSync(fullPath, content);
      }
    }
  }
}

processDir(__dirname + '/src');
processDir(__dirname + '/dashboard');
