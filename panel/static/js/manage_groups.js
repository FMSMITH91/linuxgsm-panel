// Group management page.
// Quick-role presets: tick exactly the permissions for a role in whichever form the button is in.
// Superadmin convenience only — the server still applies the anti-escalation rules on save.
(function(){
  var PRESETS = {
    moderator: ["view_servers","view_console","kick_player","ban_player","say_server"],
    admin: ["view_servers","view_console","send_command","moderate_server","kick_player","ban_player",
            "say_server","restart_server","start_server","stop_server","update_server",
            "install_server","uninstall_server","manage_servers","view_logs"],
    none: []
  };
  document.addEventListener('click', function(e){
    var btn = e.target.closest('[data-role-preset]');
    if(!btn) return;
    var form = btn.closest('form');
    if(!form) return;
    var set = PRESETS[btn.getAttribute('data-role-preset')] || [];
    form.querySelectorAll('input[name="permissions"]').forEach(function(cb){
      // Skip the ones this admin cannot grant. They render disabled (manage_groups.html) because
      // the server preserves them whatever the form says, so unticking one here would show a
      // revocation that the next save does not make.
      if(cb.disabled) return;
      cb.checked = set.indexOf(cb.value) !== -1;
    });
  });
})();
