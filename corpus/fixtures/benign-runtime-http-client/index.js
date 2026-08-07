// Runtime egress to a caller-supplied host. Nothing runs at install or
// module-load time: the app decides when and where to call.
async function getJson(baseUrl, path, fetchImpl) {
  const response = await fetchImpl(`${baseUrl}${path}`, {
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`request failed: ${response.status}`);
  }
  return response.json();
}

module.exports = { getJson };
