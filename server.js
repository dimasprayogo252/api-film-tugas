require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {authenticateToken, authorizeRole } = require('./authMiddleware');

const sql = "SELECT * FROM users WHERE username = $1";
const result = await db.query(sql, [username.toLowerCase()]);


const app = express();
const PORT = process.env.PORT || 3900;

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Server API Manajemen Film berjalan!');
});

app.get('/status', (req, res) => {
  res.json({ ok: true, service: 'film-api' });
});

// untuk user non-admin
app.post('/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6)
    return res.status(400).json({ error: 'Username dan password (min 6 char) wajib' });

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: 'Gagal hash password' });

    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    const params = [username.toLowerCase(), hashedPassword, 'user'];
    db.run(sql, params [username.toLowerCase(), hashedPassword], function(err) {
      if (err?.message.includes('UNIQUE'))
        return res.status(409).json({ error: 'Username sudah digunakan' });
      if (err) return res.status(500).json({ error: 'Gagal simpan user' });
      res.status(201).json({ message: 'Registrasi berhasil', userId: this.lastID });
    });
  });
});

//untuk user-admin
app.post('/auth/register-admin', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: 'Username dan password (min 6 char) harus diisi' });
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) { /* ... */ }

    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    const params = [username.toLowerCase(), hashedPassword, 'admin'];

    db.run(sql, params, function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(409).json({ error: 'Username admin sudah ada' });
        }
        return res.status(500).json({ error: error.message });
      }
      res.status(201).json({ message: 'Admin berhasil dibuat', userId: this.lastID });
    });
  });
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username dan password wajib' });

  db.get('SELECT * FROM users WHERE username = ?', [username.toLowerCase()], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Kredensial salah' });

    bcrypt.compare(password, user.password, (err, match) => {
      if (err || !match) return res.status(401).json({ error: 'Kredensial salah' });

      const payload = { user: { id: user.id, username: user.username, role: user.role } };
      jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
        if (err) return res.status(500).json({ error: 'Gagal buat token' });
        res.json({ message: 'Login sukses', token });
      });
    });
  });
});

app.get('/movies', (req, res) => {
  db.all('SELECT * FROM movies ORDER BY id ASC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/movies/:id', (req, res) => {
  db.get('SELECT * FROM movies WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Film tidak ditemukan' });
    res.json(row);
  });
});

app.post('/movies', authenticateToken, (req, res) => {
  const { title, director, year } = req.body;
  if (!title || !director || !year)
    return res.status(400).json({ error: 'title, director, year wajib diisi' });

  db.run('INSERT INTO movies (title, director, year) VALUES (?,?,?)', [title, director, year], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, title, director, year });
  });
});

app.put('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  const { title, director, year } = req.body;
  if (!title || !director || !year) return res.status(400).json({ error: 'wajib diisi semua' });

  db.run('UPDATE movies SET title = ?, director = ?, year = ? WHERE id = ?', [title, director, year, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'film tidak ditemukan' });
    res.json({ id: Number(req.params.id), title, director, year });
  });
});

app.delete('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  db.run('DELETE FROM movies WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Film tidak ditemukan' });
    res.status(204).send();
  });
});

// batass

app.get('/directors', (req, res) => {
  db.all('SELECT * FROM directors ORDER BY id ASC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/directors/:id', (req, res) => {
  db.get('SELECT * FROM directors WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Director tidak ditemukan' });
    res.json(row);
  });
});

app.post('/directors', authenticateToken, (req, res) => {
  const { name, birthYear } = req.body;
  if (!name || !birthYear) return res.status(400).json({ error: 'name dan birthYear wajib diisi' });

  db.run('INSERT INTO directors (name, birthYear) VALUES (?, ?)', [name, birthYear], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, name, birthYear });
  });
});

app.put('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  const { name, birthYear } = req.body;
  if (!name || !birthYear) {
    return res.status(400).json({ error: 'name dan birthYear wajib diisi' });
  }

  const sql = 'UPDATE directors SET name = ?, birthYear = ? WHERE id = ?';
  db.run(sql, [name, birthYear, req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Director tidak ditemukan' });
    }
    res.json({ id: Number(req.params.id), name, birthYear });
  });
});


// DELETE - Hapus director
app.delete('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  console.log('Request Delete /director oleh user:', req.user.username);
  const sql = 'DELETE FROM directors WHERE id = ?';
  db.run(sql, [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Director tidak ditemukan' });
    }
    res.status(204).send(); // sama kayak movies
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Rute tidak ditemukan' });
});

app.listen(PORT, () => {
  console.log(`Server aktif di http://localhost:${PORT}`);
});