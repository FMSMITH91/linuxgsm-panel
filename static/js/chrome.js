// Shared page chrome: flash auto-dismiss and the mobile sidebar.
setTimeout(function() {
  document.querySelectorAll('.alert-dismissible').forEach(function(el) {
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
