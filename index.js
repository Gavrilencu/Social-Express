const express = require('express');
require('dotenv').config();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mysql = require('mysql2/promise');
const app = express();
app.use(cors());
const PORT = 3000;
app.use(bodyParser.json());

// Configurația pool-ului de conexiuni MySQL
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
// Ruta de înregistrare
app.post('/register', async (req, res) => {
    const { name, surname, email, password } = req.body;
    const saltRounds = 10;

    try {
        const hash = await bcrypt.hash(password, saltRounds);
        const [rows] = await pool.query('INSERT INTO users (name, surname, email, password) VALUES (?, ?, ?, ?)', [name, surname, email, hash]);
        res.status(200).send({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).send({ message: 'Error registering user', error: err.message });
    }
});

// Ruta de autentificare
app.post('/auth', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).send({ message: 'User not found' });
        }
        const user = users[0];
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            res.status(200).send({ 
                message: 'Authentication successful',
                user: {
                    id: user.id,
                    name: user.name,
                    surname: user.surname
                }
            });
        } else {
            res.status(401).send({ message: 'Authentication failed' });
        }
    } catch (err) {
        res.status(500).send({ message: 'Error fetching user', error: err.message });
    }
});

app.get('/friends/:myid', async (req, res) => {
    const myid = req.params.myid;

    try {
        const [friends] = await pool.query('SELECT friendname, usercount FROM friends WHERE myid = ?', [myid]);
        const [countResult] = await pool.query('SELECT COUNT(*) AS totalFriends FROM friends WHERE myid = ?', [myid]);
        res.json({
            friends,
            totalFriends: countResult[0].totalFriends
        });
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
