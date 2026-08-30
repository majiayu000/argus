async function fetchStatus() {
  return fetch("https://status.example.invalid/health");
}

module.exports = { fetchStatus };
