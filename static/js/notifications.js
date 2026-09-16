// Notification settings form.
function _val(name) { var el = document.querySelector('[name="' + name + '"]'); return el ? el.value.trim() : ''; }
function testChannel(channel, btn) {
  var orig = btn ? btn.innerHTML : '';
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Sending…'; }
  // Send the values currently typed in the form so you can test BEFORE saving; blank fields fall
  // back to whatever's already saved.
  var payload = {channel: channel};
  if (channel === 'telegram') { payload.token = _val('telegram_token'); payload.chat_id = _val('telegram_chat_id'); }
  else if (channel === 'discord') { payload.webhook = _val('discord_webhook'); }
  else if (channel === 'discord_bot') { payload.token = _val('discord_bot_token'); payload.chat_id = _val('discord_channel_id'); }
  else if (channel === 'ntfy') { payload.token = _val('ntfy_token'); payload.server = _val('ntfy_server'); payload.topic = _val('ntfy_topic'); }
  fetch(MOUNT + '/api/notifications/test', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  })
  .then(r => r.json())
  .then(d => toast(d.message || (d.success ? 'Sent' : 'Failed'), d.success ? 'success' : 'danger'))
  .catch(function(){ toast('Request failed', 'danger'); })
  .finally(function(){ if (btn) { btn.disabled = false; btn.innerHTML = orig; } });
}
