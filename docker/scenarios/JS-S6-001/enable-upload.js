const fs = require('node:fs')

const routePath = '/juice-shop/build/routes/fileUpload.js'
const source = fs.readFileSync(routePath, 'utf8')
const guardedUpload = '((file?.buffer) != null) && utils.isChallengeEnabled(datacache_1.challenges.fileWriteChallenge)'
const enabledUpload = '((file?.buffer) != null) && true'

if (!source.includes(guardedUpload)) {
  throw new Error('JS-S6-001 upload guard was not found')
}

fs.writeFileSync(routePath, source.replace(guardedUpload, enabledUpload))
