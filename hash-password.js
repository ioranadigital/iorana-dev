// ══════════════════════════════════════════════════════════
//  Genera el hash bcrypt para tu contraseña
//  Uso: node hash-password.js
// ══════════════════════════════════════════════════════════

const bcrypt   = require("bcryptjs");
const readline = require("readline");

const rl = readline.createInterface({
  input:  process.stdin,
  output: process.stdout,
});

rl.question("Nueva contraseña: ", async (password) => {
  if (!password.trim()) {
    console.error("❌  La contraseña no puede estar vacía.");
    process.exit(1);
  }

  const hash = await bcrypt.hash(password.trim(), 12);

  console.log("\n✓  Hash generado:");
  console.log(`   ${hash}`);
  console.log("\n   Copia esta línea en tu .env:");
  console.log(`   PASSWORD_HASH=${hash}\n`);

  rl.close();
});
