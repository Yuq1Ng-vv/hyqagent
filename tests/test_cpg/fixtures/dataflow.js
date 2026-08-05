// Data flow test fixture — JavaScript
// Simple variable assignments and uses for def-use chain testing

const express = require('express');

function processRequest(req) {
    let userInput = req.query.id;   // def: userInput
    let sanitized = parseInt(userInput);  // def: sanitized, use: userInput
    let result = lookup(sanitized);  // def: result, use: sanitized
    return result;  // use: result
}

function lookup(itemId) {
    let query = `SELECT * FROM users WHERE id=${itemId}`;  // def: query, use: itemId (param)
    let data = dbExecute(query);  // def: data, use: query
    return data;  // use: data
}

function dbExecute(sql) {
    console.log(`Executing: ${sql}`);  // use: sql (param)
}

function multiAssign() {
    let x = 1;   // def: x
    let y = x + 1;  // def: y, use: x
    x = y * 2;  // def: x (re-def), use: y
    return x;  // use: x
}
