require('dotenv').config(); 

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const app = express();
const port = process.env.PORT || 4000;

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// bcrypt, pbkdf2, aes
const saltrounds = 10;
const keylength = 32;
const nonce = 16;
const pbkdf2times = 100000;

// connect to db 
const db = new Pool({
  connectionString: process.env.DATABASE_URL,

});

app.use(cors());
app.use(express.json()); 

//SIGNUP PAGE
// make a new user
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'need both username and password' });

  try {
    const existing = await db.query('select * from users where username = $1', [username]);
    if (existing.rows.length > 0)
      return res.status(400).json({ message: 'username already taken :P' });

    const hash = await bcrypt.hash(password, saltrounds);

    const result = await db.query(
      'insert into users (username, password) values ($1, $2) returning id, username',
      [username, hash]
    );

    res.status(201).json({ message: 'account created!', user: result.rows[0] });
  } catch (err) {
    console.error('signup error:', err);
    res.status(500).json({ message: 'something broke QAQ' });
  }
});

// login endpoint (checks password and gives token)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'need username and password pls' });

  try {
    const result = await db.query('select * from users where username = $1', [username]);
    
    if (result.rows.length === 0)
      return res.status(400).json({ message: 'bad username/password' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match)
      return res.status(400).json({ message: 'bad username/password' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'Logged in!',
      username: user.username,
      token,
    });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ message: 'something wrong withoserver' });
  }
});

// password + salt into encryption key
function getKey(password, salthex) {
  const salt = Buffer.from(salthex, 'hex');

  return crypto.pbkdf2Sync(password, salt, pbkdf2times, keylength, 'sha256');
}

// FOR THE PASSWORD VAULT
// encrypt password stuff and save saving diff mastrpass
function encrypt(text, masterPassword) {
  const salt = crypto.randomBytes(16); // to make new salt so not all passswords have the same on
  
  const salthex = salt.toString('hex');
  const iv = crypto.randomBytes(nonce);
  const key = getKey(masterPassword, salthex);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');

  return {
    encrypted,
    iv: iv.toString('hex'),
    salt: salthex,
  };

}

// decrypt stuff using the same password + salt
function decrypt(encrypted, ivHex, masterPassword, salthex) {
  const iv = Buffer.from(ivHex, 'hex');
  const key = getKey(masterPassword, salthex);

  const decrypt = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return decrypt.update(encrypted, 'hex', 'utf8') + decrypt.final('utf8');
}

// check jwt and adds user info to request
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1]; // the formatting

  if (!token) return res.status(401).json({ message: 'no token ' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (oops) {
    return res.status(403).json({ message: 'invalid token' });
  }
};



// saves a password entry
app.post('/vault/add', authenticate, async (req, res) => {
  const { site, login, password, masterPassword } = req.body;

  if (!site || !login || !password || !masterPassword)
    return res.status(400).json({ message: 'missing stuff, check your fields' });

  try {
    const { encrypted, iv, salt } = encrypt(password, masterPassword);

    await db.query(
      `insert into vault (user_id, site, login, encrypted_password, iv, salt)
       values ($1, $2, $3, $4, $5, $6)`,
      [req.userId, site, login, encrypted, iv, salt]
    );

    res.status(201).json({ message: 'saved! ' });
  } catch (err) {
    console.error('vault add error:', err);

    res.status(500).json({ message: 'server issue' });
  }
});

// gets all saved entries as decrypted
app.post('/vault/list', authenticate, async (req, res) => {
  const { masterPassword } = req.body;

  if (!masterPassword)
    return res.status(400).json({ message: 'enter a master password' });

  try {
    const result = await db.query('select * from vault where user_id = $1', [req.userId]);

    const passwords = result.rows.map((entry) => {
      try {
        const realPw = decrypt(
          entry.encrypted_password,
          entry.iv,
          masterPassword,
          entry.salt
        );

        return {
          site: entry.site,
          login: entry.login,
          password: realPw,
        };
      } catch {
        // couldn't decrypt, probably wrong master password
        return {
          site: entry.site,
          login: entry.login,
          password: '****',
        };
      }
    });

    res.json(passwords);
  } catch (err) {
    console.error('vault list error:', err);
    res.status(500).json({ message: 'could not fetch entries' });
  }
});

app.listen(port, () => {
  console.log(`server is live ${port}`);
});
