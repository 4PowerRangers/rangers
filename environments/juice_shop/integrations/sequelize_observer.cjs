'use strict'

// Observe Sequelize's existing query logging path without changing Juice Shop's
// SQLite database or persisting SQL. Raw SQL exists only in this UDP datagram;
// Rangers immediately reduces it to operation/table/behavior facts.
const dgram = require('node:dgram')

const destination = process.env.RANGERS_DB_OBSERVER
const token = process.env.RANGERS_DB_OBSERVER_TOKEN
const sequenceDestination = process.env.RANGERS_SEQUENCE_OBSERVER
const sequenceToken = process.env.RANGERS_SEQUENCE_TOKEN
const observerConfigured = destination && token && sequenceDestination && sequenceToken
if (!observerConfigured) {
  const partial = Boolean(destination || token) && !Boolean(sequenceDestination && sequenceToken)
  console.warn(
    partial
      ? 'RANGERS DB observer disabled: configuration incomplete; sequence observer env not set. R5 state-diff evidence will be unavailable in this run.'
      : 'RANGERS DB observer disabled: required observer env not set. R5 state-diff evidence will be unavailable in this run.'
  )
}
if (observerConfigured) {
  const separator = destination.lastIndexOf(':')
  const host = destination.slice(0, separator)
  const port = Number(destination.slice(separator + 1))

  if (host && Number.isInteger(port) && port > 0 && port < 65536) {
    const client = dgram.createSocket('udp4')
    client.on('error', () => {})
    client.unref()
    const { Sequelize } = require('sequelize')
    const originalLog = Sequelize.prototype.log

    Sequelize.prototype.log = function (sql, ...args) {
      if (typeof sql === 'string') {
        // The sequence service may be briefly unreachable (host process still
        // starting, or torn down between runs). A failed lookup must never
        // crash Juice Shop, so the query event is dropped, not the request.
        try {
          const seq = require('node:child_process').execFileSync(
            process.execPath,
            ['-e', `const net=require('node:net');const c=net.createConnection(${JSON.stringify(Number(sequenceDestination?.split(':').pop()))},${JSON.stringify(sequenceDestination?.split(':').slice(0,-1).join(':'))});c.on('error',()=>process.exit(1));c.on('connect',()=>c.end(JSON.stringify({token:${JSON.stringify(sequenceToken)}})+'\\n'));let d='';c.on('data',x=>d+=x);c.on('end',()=>process.stdout.write(d));`],
            { encoding: 'utf8', timeout: 5000 }
          )
          const parsed = JSON.parse(seq).seq
          if (Number.isInteger(parsed) && parsed >= 0) {
            const payload = Buffer.from(JSON.stringify({
              timestamp: new Date().toISOString(),
              seq: parsed,
              token,
              sql: sql.slice(0, 16384)
            }))
            client.send(payload, port, host)
          }
        } catch {
          // sequence lookup failed; skip this event rather than fail the query
        }
      }
      return originalLog.call(this, sql, ...args)
    }
  }
}
