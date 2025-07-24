
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
const db = new sqlite3.Database('pilots.db');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Vytvoření tabulky, pokud neexistuje
db.run(`CREATE TABLE IF NOT EXISTS pilots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  location TEXT,
  email TEXT,
  phone TEXT,
  note TEXT,
  latitude REAL,
  longitude REAL,
  password_hash TEXT,
  website TEXT,
  city TEXT,
  street TEXT,
  zip TEXT,
  region TEXT,
  licenses TEXT,
  drones TEXT,
  travel TEXT
)`);

// Přihlášení
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM pilots WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(401).send("Uživatel nenalezen.");
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).send("Nesprávné heslo.");
    res.send("Přihlášení úspěšné");
  });
});

// Registrace
app.post('/register', async (req, res) => {
  const {
    name, email, password, phone, website,
    city, street, zip, region,
    licenses, drones, note, travel
  } = req.body;

  const password_hash = await bcrypt.hash(password, 10);
  const location = [street, city, zip, region].filter(Boolean).join(', ');
  let lat = null, lon = null;

  try {
    const response = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(location)}&limit=1`, {
      headers: { 'User-Agent': 'DronMapApp/1.0' }
    });
    const data = await response.json();
    if (data.length > 0) {
      lat = parseFloat(data[0].lat);
      lon = parseFloat(data[0].lon);
    }
  } catch (err) {
    console.error("Chyba při geokódování:", err);
  }

  const licenseList = Array.isArray(licenses) ? licenses.join(', ') : (licenses || '');

  db.run(
    `INSERT INTO pilots (
      name, email, phone, website,
      city, street, zip, region,
      licenses, drones, note, travel,
      latitude, longitude, password_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, email, phone, website, city, street, zip, region, licenseList, drones, note, travel, lat, lon, password_hash],
    (err) => {
      if (err) {
        console.error("Chyba při registraci:", err);
        res.status(500).send("Chyba při registraci");
      } else {
        res.redirect('/');
      }
    }
  );
});

// Vrácení všech pilotů
app.get('/pilots', (req, res) => {
  db.all(`SELECT * FROM pilots`, (err, rows) => {
    if (err) return res.status(500).json([]);
    res.json(rows);
  });
});

// Odstranění všech pilotů
app.post('/delete-all', (req, res) => {
  db.run(`DELETE FROM pilots`, (err) => {
    if (err) return res.status(500).send("Chyba při mazání");
    res.send("Všechny záznamy byly smazány.");
  });
});

// 💌 Odeslání nového hesla pomocí Seznam.cz
const transporter = nodemailer.createTransport({
    host: 'smtp.seznam.cz',
  port: 465,
  secure: true,
auth: {
  user: 'dronadmin@seznam.cz',
  pass: 'letamsdrony12'
}
});

app.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("E-mail je povinný.");

  db.get(`SELECT * FROM pilots WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(404).send("Uživatel s tímto e-mailem nebyl nalezen.");

    const newPassword = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(newPassword, 10);

    db.run(`UPDATE pilots SET password_hash = ? WHERE email = ?`, [hash, email], async (err) => {
      if (err) return res.status(500).send("Chyba při ukládání nového hesla.");

      try {
        await transporter.sendMail({
          from: '"Dronová mapa" <dronadmin@seznam.cz>',
          to: email,
          subject: "Nové heslo k účtu",
          text: `Vaše nové heslo je: ${newPassword}


Doporučujeme jej po přihlášení ihned změnit.`
        });
console.log(`📧 Heslo odeslané na ${email}: ${newPassword}`);
        res.send("Nové heslo bylo odesláno na váš e-mail.");
      } catch (e) {
  console.error("❌ Chyba při odesílání e-mailu:", e);
  res.status(500).send("E-mail se nepodařilo odeslat. Zkontrolujte konfiguraci.");
}
    });
  });
});
app.use(express.json());
app.post("/update", (req, res) => {
  const {
    email,
    name,
    phone,
    website,
    street,
    city,
    zip,
    region,
    drones,
    note,
    travel,
    licenses,
    specialization,
    volunteer
  } = req.body;

  db.run(
    `UPDATE pilots SET 
      name = ?, 
      phone = ?, 
      website = ?, 
      street = ?, 
      city = ?, 
      zip = ?, 
      region = ?, 
      drones = ?, 
      note = ?, 
      travel = ?, 
      licenses = ?, 
      specialization = ?, 
      volunteer = ? 
    WHERE email = ?`,
    [
      name || "",
      phone || "",
      website || "",
      street || "",
      city || "",
      zip || "",
      region || "",
      drones || "",
      note || "",
      travel || "",
      licenses || "",
      specialization || "",
      volunteer === "ANO" ? "ANO" : "NE",
      email
    ],
    function (err) {
      if (err) {
        console.error(err);
        res.status(500).send("Chyba při ukládání dat.");
      } else {
        res.send("✅ Údaje byly úspěšně uloženy.");
      }
    }
  );
});

app.post('/delete-selected', (req, res) => {
  const ids = req.body.ids;
  if (!Array.isArray(ids)) {
    return res.status(400).send('Neplatný vstup – očekává se pole ID.');
  }

  const beforeCount = pilots.length;
  pilots = pilots.filter(p => !ids.includes(p.id));
  const afterCount = pilots.length;

  fs.writeFileSync('pilots.json', JSON.stringify(pilots, null, 2));
  res.send(`Smazáno ${beforeCount - afterCount} pilotů.`);
});
app.listen(3000, () => console.log('Server běží na http://localhost:3000'));
