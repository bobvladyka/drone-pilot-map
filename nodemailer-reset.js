
// 📧 Konfigurace e-mailového odesílače pomocí Nodemailer
const nodemailer = require('nodemailer');

// ⚠️ Nahraď svými skutečnými údaji (použij heslo aplikace z Gmailu)
const transporter = nodemailer.createTransport({
  host: 'smtp.seznam.cz',
  port: 465,
  secure: true, // true = SSL
  auth: {
    user: 'dronadmin@seznam.cz',
    pass: 'letamsdrony12'
  }
});

// Reset hesla s odesláním e-mailem
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("E-mail je povinný.");

  db.get(`SELECT * FROM pilots WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) {
      return res.status(404).send("Uživatel s tímto e-mailem nebyl nalezen.");
    }

    const newPassword = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(newPassword, 10);

    db.run(`UPDATE pilots SET password_hash = ? WHERE email = ?`, [hash, email], async (err) => {
      if (err) {
        console.error("Chyba při ukládání nového hesla:", err);
        return res.status(500).send("Chyba při ukládání nového hesla.");
      }

      // Odeslání e-mailu s novým heslem
      try {
        await transporter.sendMail({
          from: '"Dronová mapa" <TVŮJ_EMAIL@gmail.com>',
          to: email,
          subject: "Nové heslo k účtu",
          text: `Vaše nové heslo: ${newPassword}

Doporučujeme jej po přihlášení ihned změnit.`
        });
        res.send("Nové heslo bylo zasláno na váš e-mail.");
      } catch (mailErr) {
        console.error("Chyba při odesílání e-mailu:", mailErr);
        res.status(500).send("Heslo bylo vytvořeno, ale e-mail se nepodařilo odeslat.");
      }
    });
  });
});
