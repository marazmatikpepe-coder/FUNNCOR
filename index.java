// server/auth-server/index.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        // Проверка существования
        const existing = await pool.query(
            'SELECT id FROM users WHERE username = $1 OR email = $2',
            [username, email]
        );
        
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'Пользователь уже существует' });
        }
        
        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Создание пользователя
        const result = await pool.query(
            `INSERT INTO users (username, email, password_hash, created_at, coins, level)
             VALUES ($1, $2, $3, NOW(), 100, 1)
             RETURNING id, username, coins, level`,
            [username, email, hashedPassword]
        );
        
        const user = result.rows[0];
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            success: true, 
            token, 
            user: {
                id: user.id,
                username: user.username,
                coins: user.coins,
                level: user.level
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Вход
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Неверные данные' });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Неверные данные' });
        }
        
        // Обновляем last_login
        await pool.query(
            'UPDATE users SET last_login = NOW() WHERE id = $1',
            [user.id]
        );
        
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            success: true, 
            token,
            user: {
                id: user.id,
                username: user.username,
                coins: user.coins,
                level: user.level,
                inventory: user.inventory
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Middleware для проверки токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Токен не предоставлен' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Недействительный токен' });
        }
        req.userId = decoded.userId;
        next();
    });
}

// Получение профиля
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, username, email, coins, level, experience, 
                    inventory, avatar_data, created_at
             FROM users WHERE id = $1`,
            [req.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        res.json({ user: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Сохранение данных игрока
app.post('/api/save-progress', authenticateToken, async (req, res) => {
    const { coins, experience, inventory, position } = req.body;
    
    try {
        await pool.query(
            `UPDATE users 
             SET coins = $1, experience = $2, inventory = $3, 
                 last_position = $4, updated_at = NOW()
             WHERE id = $5`,
            [coins, experience, JSON.stringify(inventory), 
             JSON.stringify(position), req.userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сохранения' });
    }
});

app.listen(3001, () => {
    console.log('Auth server running on port 3001');
});

module.exports = { app, authenticateToken };
