// The share token travels in the URL fragment (#...), which browsers never send
// to the server: it stays out of server logs, proxies and Referer headers.
// This script moves it into POST bodies instead.
(function () {
  var token = decodeURIComponent((window.location.hash || "").replace(/^#/, ""));
  var status = document.getElementById("share-status");
  if (!token) { status.textContent = "This link is incomplete."; return; }
  history.replaceState(null, "", window.location.pathname); // drop it from the address bar
  fetch("/api/share/info", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: token }),
    credentials: "omit"
  }).then(function (r) {
    if (!r.ok) { throw new Error(r.status); }
    return r.json();
  }).then(function (info) {
    document.getElementById("share-name").textContent = info.name;
    document.getElementById("share-size").textContent = (info.size_bytes / 1024).toFixed(1) + " KB";
    document.getElementById("share-expiry").textContent = new Date(info.expires_at).toLocaleString();
    if (info.downloads_remaining !== null) {
      document.getElementById("share-remaining").textContent = " · " + info.downloads_remaining + " download(s) left";
    }
    document.getElementById("share-token").value = token;
    document.getElementById("share-details").hidden = false;
    status.hidden = true;
  }).catch(function () {
    status.textContent = "This link is invalid, expired, used up or revoked.";
  });
})();
