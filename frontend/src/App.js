import './App.css';
import React, { useState } from 'react';
import {BrowserRouter as Router,Routes,Route,Link,Navigate} from 'react-router-dom';
import axios from 'axios';

// login form 
function Login({ setUser }) {
  const [username, setUsername] = useState('');
  const [pwd, setPwd] = useState('');
  const [err, setErr] = useState('');

  // login
  const tryLogin = async (e) => {
    e.preventDefault();

    try {
      const loginRes = await axios.post('http://localhost:4000/login', {
        username: username,
        password: pwd,
      });

      setUser(loginRes.data.username); 
      localStorage.setItem('token', loginRes.data.token); // store for later
    } catch (err) {
      setErr(err?.response?.data?.message || 'login didnt work');
    }
  };

  //DONT TOUCH UR GONNA BREAK IT
  return (
    <div>
      <h2>Login</h2>
      {err && <p style={{ color: 'red' }}>{err}</p>}
      <form onSubmit={tryLogin}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={pwd}
          onChange={(e) => setPwd(e.target.value)}
          required
        />
        <button type="submit">Login</button>
      </form>
      <p>
        no account? <Link to="/signup">Sign Up</Link>
      </p>
    </div>
  );
}

// sign up
function Signup() {
  const [newUser, setNewUser] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [msg, setMsg] = useState('');
  const [failed, setFailed] = useState('');

  // creates an account
  const handleSignup = async (e) => {
    e.preventDefault();

    try {
      await axios.post('http://localhost:4000/signup', {
        username: newUser,
        password: newPwd,
      });

      setMsg('user created login now.');
      setFailed('');
      setNewUser('');
      setNewPwd('');

    } catch (err) {
      setFailed(err?.response?.data?.message || 'signup not working');
      setMsg('');
    }
  };

  // DONT CHANGE
  return (
    <div>
      <h2>Sign Up</h2>
      {msg && <p style={{ color: 'green' }}>{msg}</p>}
      {failed && <p style={{ color: 'red' }}>{failed}</p>}
      <form onSubmit={handleSignup}>
        <input
          type="text"
          placeholder="Username"
          value={newUser}
          onChange={(e) => setNewUser(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={newPwd}
          onChange={(e) => setNewPwd(e.target.value)}
          required
        />
        <button type="submit">Sign Up</button>
      </form>
      <p>
        have account? <Link to="/">Login</Link>
      </p>
    </div>
  );
}

// welcome page after loged in
function Welcome({ user, setUser }) {
  if (!user) return <Navigate to="/" />;

  const logoutUser = () => {
    setUser(null);
    localStorage.removeItem('token'); // forget token
  };

  return (
    <div>
      <h2>You are ogged in, welcome! {user}</h2>
      <button onClick={logoutUser}>Logout</button>
      <p>
        <Link to="/manager">Go to Password Manager</Link>
      </p>
    </div>
  );
}



// -----------------------------------------------------------------------------------





// PASSWORD VAULT 
function Vault({ token }) {
  const [site, setSite] = useState('');
  const [login, setLogin] = useState('');
  const [pw, setPw] = useState('');
  const [master, setMaster] = useState('');
  const [seeKey, setSeeKey] = useState('');
  const [saved, setSaved] = useState([]);
  const [see, setSee] = useState(false);

  // add passto the vault
  const savePassword = async () => {
    if (!master) {
      alert('please type master password!');
      return;
    }

    try {

      await axios.post(
        'http://localhost:4000/vault/add',
        {
          site: site,
          login: login,
          password: pw,
          masterPassword: master,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      alert('password saved!');
      setSite('');
      setLogin('');
      setPw('');

    } catch (err) {
      console.log('save error:', err);
      alert('couldnt save password');
    }
  };

  // unlocks saved passwords
  const fetchPasswords = async () => {
    if (!seeKey) {
      alert('need the view password key');
      return;
    }

    try {
      const res = await axios.post(
        'http://localhost:4000/vault/list',
        {
          masterPassword: seeKey,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setSaved(res.data);
      setSee(true);
    } catch (err) {
      console.error('unlock failed', err);
      alert('wrong view key or something broke');
      setSee(false);
      setSaved([]);
    }
  };

  // odnt change
  return (
    <div>
      <h2>Password Vault</h2>

      <h3>Add New Entry</h3>
      <input
        placeholder="Master Password (to encrypt)"
        type="password"
        value={master}
        onChange={(e) => setMaster(e.target.value)}
      />
      <input
        placeholder="Site"
        value={site}
        onChange={(e) => setSite(e.target.value)}
      />
      <input
        placeholder="Login"
        value={login}
        onChange={(e) => setLogin(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
      />
      <button onClick={savePassword}>Add</button>

      <h3>Unlock Saved Passwords</h3>
      <input
        placeholder="Enter Master Password"
        type="password"
        value={seeKey}
        onChange={(e) => setSeeKey(e.target.value)}
      />
      <button onClick={fetchPasswords}>Unlock Passwords</button>

      {see ? (
        <>
          <h3>Saved Passwords</h3>
          <ul>
            {saved.map((entry, idx) => (
              <li key={idx}>
                {entry.site} - {entry.login}: {entry.password}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p style={{ color: 'gray' }}>
          Enter a master password to see saved passwords.
        </p>
      )}
    </div>
  );
}

//Pages
function App() {
  const [user, setUser] = useState(null);
  const token = localStorage.getItem('token'); // yay persistence

  return (
    <Router>
      <Routes>
        <Route
          path="/"
          element={
            user ? <Navigate to="/welcome" /> : <Login setUser={setUser} />
          }
        />
        <Route path="/signup" element={<Signup />} />
        <Route
          path="/welcome"
          element={<Welcome user={user} setUser={setUser} />}
        />
        <Route path="/manager" element={<Vault token={token} />} />
      </Routes>
    </Router>
  );
}

export default App;
