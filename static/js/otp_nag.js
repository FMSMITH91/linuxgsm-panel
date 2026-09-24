// The "turn on 2FA" reminder banner.
// Show unless suppressed for this browser session ("Not now"). Permanent dismissal is stored
// server-side, so if we got here the account hasn't chosen "Don't remind me again".
(function(){ var n=document.getElementById('otp-nag'); if(!n) return;
  if(sessionStorage.getItem('otpNagHidden')==='1'){ n.remove(); } else { n.style.display=''; } })();
function hideOtpNag(session){ var n=document.getElementById('otp-nag'); if(n) n.remove();
  if(session){ try{ sessionStorage.setItem('otpNagHidden','1'); }catch(e){} } }
function dismissOtpNagForever(){
  confirmDialog({title:'Stop reminding me', icon:'bell-slash', confirmClass:'btn-warning', confirmLabel:"Don't remind me",
    bodyText:'Permanently hide the two-factor reminder for your account? You can still turn 2FA on any time from your Account page.',
    onConfirm:function(){
      // The reply is checked, not just parsed: a failed save still answers parseable JSON
      // ({success:false} with a 500), and treating any JSON as success removed the banner and said
      // "You won't be reminded again" about a choice that was never stored.
      fetch(MOUNT + '/account/2fa/dismiss-nag', {method:'POST'})
        .then(function(r){ return r.json().then(function(d){ return {ok: r.ok, d: d}; }); })
        .then(function(x){
          if (!(x.ok && x.d && x.d.success)) throw 0;
          hideOtpNag(false); if(window.toast) toast("You won't be reminded again.", 'info');
        })
        .catch(function(){ if(window.toast) toast('Could not save that — please try again.', 'danger'); });
    }});
}
