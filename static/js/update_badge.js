// Panel update pill in the sidebar (super admins only).
// Panel update badge (super admins only). Quietly checks if the panel is behind
// its GitHub repo and shows an "update" pill next to the version in the sidebar.
(function(){
  var badge = document.getElementById('update-badge');
  if (!badge) return;
  function check(){
    fetch(window.MOUNT + '/api/panel/update-status', {cache: 'no-store'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (d && d.update_available) {
          badge.innerHTML = ' <a href="' + window.MOUNT + '/server-management#updates" '  // nosemgrep - MOUNT is server-rendered panel config and the version is escapeHtml output
            + 'style="color:#d29922;text-decoration:none;font-weight:600;" '
            + 'title="Version ' + escapeHtml(d.remote_version||'') + ' is available — click to update">'
            + '<i class="bi bi-arrow-up-circle-fill"></i> update</a>';
        } else if (d && d.update_available === false) {
          badge.innerHTML = '';   // definitively up to date (e.g. after updating) — clear the pill
        }
        // a malformed/failed response leaves the badge as-is (don't hide a real update)
      })
      .catch(function(){});
  }
  check();
  // Re-check periodically so a newly released update shows up WITHOUT a manual reload, and a
  // transient first-check failure ("sometimes it doesn't show") self-heals on the next tick.
  if (window.pollWhenVisible) window.pollWhenVisible(check, 15 * 60 * 1000);
  else setInterval(check, 15 * 60 * 1000);
})();
