const express = require('express');
const router = express.Router();
const pool = require('../config');
const SQLInjectionDetector = require('./sqlinject'); // Import the SQLInjectionDetector class

const checkNotLoggedIn = (req, res, next) => {
    if (req.session.userId) {
        return res.redirect(req.session.role === 'admin' ? '/admin' : '/user');
    }
    next();
};

const preventBackButtonCache = (req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
};

router.get('/login', checkNotLoggedIn, preventBackButtonCache, (req, res) => {
    res.render('login', { error: null });
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const detector = new SQLInjectionDetector(); // Create an instance of SQLInjectionDetector

    // Prepare the SQL query
    const sqlQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    // Detect SQL injection
    const userInputs = [username, password];
    const injectionResult = detector.detect(sqlQuery, userInputs);

    if (injectionResult.isInjection) {
        console.log(`SQL Injection detected: ${injectionResult.reason}, Tainted String: ${injectionResult.taintedString}`);
        return res.status(400).render('login', { error: 'SQL Injection attempt detected' });
    }

    try {
        const rows = await pool.query(sqlQuery);

        if (rows.length > 0) {
            const user = rows[0];
            const match = password === user.password;

            if (match) {
                req.session.userId = user.id;
                req.session.role = user.role;

                if (user.role === 'admin') {
                    return res.redirect('/admin');
                } else {
                    return res.redirect('/user');
                }
            } else {
                return res.render('login', { error: 'Incorrect password' });
            }
        } else {
            return res.render('login', { error: 'User not found' });
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send('Server error');
    }
});

// Logout route
router.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out');
        }
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.redirect('/login');
    });
});

module.exports = router;
