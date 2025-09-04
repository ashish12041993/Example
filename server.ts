import express from "express";
import bodyParser from "body-parser";
import { exec } from "child_process";
import sqlite3 from "sqlite3";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// :x: Hardcoded secret (insecure)
const JWT_SECRET = "mysecret";
// :x: In-memory DB, no sanitation
const db = new sqlite3.Database(":memory:");
// Create demo table
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("INSERT INTO users (username, password) VALUES ('admin','password')");
});
// Vulnerable login (SQL Injection + JWT misuse)
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  // :x: SQL Injection: unsanitized string concatenation
  db.get(
    `SELECT * FROM users WHERE username='${username}' AND password='${password}'`,
    (err, row) => {
      if (row) {
        // :x: JWT issued with hardcoded secret, no expiration
        const token = jwt.sign({ user: row.username }, JWT_SECRET);
        res.json({ token });
      } else {
        res.status(401).send("Invalid credentials");
      }
    }
  );
});
// Vulnerable file server (Path Traversal)
app.get("/files", (req, res) => {
  const fileName = req.query.name as string;
  // :x: Directly concatenates user input
  const filePath = path.join(__dirname, "uploads", fileName);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(404).send("File not found");
    res.send(data);
  });
});
// Vulnerable command execution
app.get("/ping", (req, res) => {
  const host = req.query.host as string;
  // :x: Command injection risk
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) return res.status(500).send("Error");
    res.send(stdout);
  });
});
// Vulnerable XSS endpoint
app.get("/greet", (req, res) => {
  const name = req.query.name as string;
  // :x: Reflects input directly in HTML
  res.send(`<h1>Hello, ${name}!</h1>`);
});
// Insecure admin panel (no auth required)
app.get("/admin", (req, res) => {
  res.send("<h2>Welcome to Admin Panel. No auth required!</h2>");
});
// Start server
app.listen(3000, () => {
  console.log("Vulnerable server running on http://localhost:3000");
});
