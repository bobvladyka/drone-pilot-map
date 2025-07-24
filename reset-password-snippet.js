
// Reset hesla
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("E-mail je povinný.");

  db.get(`SELECT * FROM pilots WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) {
      return res.status(404).send("Uživatel s tímto e-mailem nebyl nalezen.");
    }

    // Generuj nové heslo
    const newPassword = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(newPassword, 10);

    // Ulož nové heslo
    db.run(`UPDATE pilots SET password_hash = ? WHERE email = ?`, [hash, email], (err) => {
      if (err) {
        console.error("Chyba při ukládání nového hesla:", err);
        return res.status(500).send("Chyba při ukládání nového hesla.");
      }

      // Simuluj odeslání e-mailu (místo toho zobrazíme výstup na serveru)
      console.log(`🔐 Nové heslo pro ${email}: ${newPassword}`);
      res.send("Nové heslo bylo vygenerováno a zasláno na váš e-mail.");
    });
  });
});
