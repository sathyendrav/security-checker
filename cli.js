#!/usr/bin/env node
'use strict';

const check = require('./check.js');

async function run() {
  try {
    const threatsFound = await check();
    process.exit(threatsFound ? 1 : 0);
  } catch (err) {
    console.error('❌ Security check failed:', err.message);
    process.exit(1);
  }
}

run();
