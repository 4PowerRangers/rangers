const fs = require('node:fs')
const { spawn } = require('node:child_process')

const target = '/juice-shop/ftp/legal.md'
const baseline = '# Legal Information\n\nWelcome to the Juice Shop training environment.\nThis is the original legal notice for the isolated lab instance.\n'

function ensureProofTarget() {
  fs.mkdirSync('/juice-shop/ftp', { recursive: true })
  if (!fs.existsSync(target)) fs.writeFileSync(target, baseline)
  fs.mkdirSync('/juice-shop/uploads/complaints', { recursive: true })
}

ensureProofTarget()

const child = spawn('/nodejs/bin/node', ['/juice-shop/build/app.js'], {
  cwd: '/juice-shop', stdio: 'inherit', env: process.env,
})
// Juice Shop may initialize its FTP tree during startup. Keep the designated
// baseline present until the app is ready; never replace an existing proof.
const guard = setInterval(ensureProofTarget, 100)
child.on('exit', (code, signal) => {
  process.exit(code ?? (signal ? 1 : 0))
})
