import express from 'express';
import { exec } from 'child_process';
import * as mysql from 'mysql';
import * as fs from 'fs';

const app = express();
app.use(express.json());

// Create MySQL connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password123', // Vulnerability 1: Hardcoded credentials
    database: 'test_db'
});

app.get('/user/:id', (req, res) => {
    // Vulnerability 2: SQL Injection
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    connection.query(query, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.post('/execute', (req, res) => {
    // Vulnerability 3: Command Injection
    const userCommand = req.body.command;
    exec(userCommand, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

app.get('/render', (req, res) => {
    // Vulnerability 4: Cross-site Scripting (XSS)
    const userInput = req.query.content;
    res.send(`<div>${userInput}</div>`);
});

app.get('/download', (req, res) => {
    // Vulnerability 5: Path Traversal
    const fileName = req.query.file;
    const filePath = `./files/${fileName}`;
    fs.readFile(filePath, (err, data) => {
        if (err) throw err;
        res.send(data);
    });
});

// Vulnerability 6: Weak Cryptography
function encryptPassword(password: string): string {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(password).digest('hex');
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
