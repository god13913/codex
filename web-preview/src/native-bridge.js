const webview = window.chrome?.webview;

if (webview) {
  const pending = new Map();
  let nextId = 0;
  webview.addEventListener('message', event => {
    const message = event.data;
    if (!message || typeof message.id !== 'number') return;
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(message.error));
    else request.resolve(message.result);
  });
  const request = (method, payload = null) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    try { webview.postMessage({ id, method, payload }); }
    catch (error) { pending.delete(id); reject(error); }
  });
  window.codexProxy = {
    native: true,
    request,
    getNodeExitIpv4: profile => request('getNodeExitIpv4', profile),
  };
}
