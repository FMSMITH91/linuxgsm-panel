// Shared page chrome: flash auto-dismiss and the mobile sidebar.
//
// SCOPED TO .flash-container. This selected every `.alert-dismissible` in the document, and
// nags.js gives the OS-updates banner that class to park its close button — so the panel's
// "System updates waiting / N security" warning erased itself six seconds after every page load,
// without recording a dismissal, and flickered back on the next visibility poll. A flash message
// is a transient reply to something the user just did and is right to time out; a standing
// warning is not, and nothing but the flash container should be swept.
setTimeout(function() {
  document.querySelectorAll('.flash-container .alert-dismissible').forEach(function(el) {
    try { bootstrap.Alert.getOrCreateInstance(el).close(); } catch(e) {}
  });
}, 6000);

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-backdrop').classList.toggle('show');
}
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.sidebar-nav a').forEach(function(link) {
    link.addEventListener('click', function() {
      if (window.innerWidth < 768) {
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebar-backdrop').classList.remove('show');
      }
    });
  });
});
