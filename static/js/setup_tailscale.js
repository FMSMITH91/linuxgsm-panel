// Tailscale step of the setup wizard.
function tsEsc(s){ return window.escapeHtml(s); }
function tsApi(p, opts){ return fetch((window.MOUNT||'') + '/api/setup/tailscale/' + p, opts).then(function(r){ return r.json(); }); }  // nosemgrep
var tsBox = document.getElementById('ts-box');
var tsCont = document.getElementById('ts-continue');

function tsRefresh(){ return tsApi('status').then(function(s){ tsRender(s); return s; }).catch(function(){ tsBox.innerHTML='<div class="text-danger small">Could not check Tailscale status.</div>'; }); }

function tsRender(s){
  if(s.error){ tsBox.innerHTML='<div class="text-danger small">'+tsEsc(s.error)+'</div>'; return; }  // nosemgrep - tsEsc is window.escapeHtml
  if(s.running && s.dns_name){
    if(s.serve_url){
      tsBox.innerHTML='<div class="alert alert-success py-2 small mb-2"><i class="bi bi-check-circle-fill"></i> '  // nosemgrep - literals plus a tsEsc-wrapped dns_name
        + 'Connected and serving over HTTPS at<br><a href="'+tsEsc(s.https_url)+'" target="_blank" style="word-break:break-all;">'+tsEsc(s.https_url)+'</a></div>'
        + '<div class="text-secondary small">Finish setup, then reach the panel at that private HTTPS URL.</div>';
      tsCont.innerHTML='<i class="bi bi-arrow-right"></i> Continue';
      tsCont.className='btn btn-primary w-100';
    } else {
      tsBox.innerHTML='<div class="alert alert-info py-2 small mb-2"><i class="bi bi-check-circle"></i> Connected to your tailnet as <code>'+tsEsc(s.dns_name)+'</code>.</div>'  // nosemgrep - literals plus a tsEsc-wrapped dns_name
        + '<button type="button" class="btn btn-success w-100" id="ts-serve"><i class="bi bi-lock-fill"></i> Enable private HTTPS (Tailscale Serve)</button>'
        + '<div id="ts-msg" class="small mt-2"></div>';
      document.getElementById('ts-serve').onclick=tsDoServe;
    }
    return;
  }
  if(s.installed && !s.running){
    tsBox.innerHTML='<div class="small text-secondary mb-2">Tailscale is installed but not connected to a tailnet yet.</div>'
      + '<button type="button" class="btn btn-primary w-100" id="ts-up"><i class="bi bi-box-arrow-up-right"></i> Connect to my tailnet</button>'
      + '<div id="ts-out" class="small mt-2"></div>';
    document.getElementById('ts-up').onclick=tsDoUp;
    return;
  }
  tsBox.innerHTML='<div class="small text-secondary mb-2">Tailscale isn\'t installed on this host yet.</div>'
    + '<button type="button" class="btn btn-primary w-100" id="ts-install"><i class="bi bi-download"></i> Install &amp; connect Tailscale</button>'
    + '<div id="ts-out" class="small mt-2"></div>';
  document.getElementById('ts-install').onclick=tsDoInstall;
}

function tsOut(){ return document.getElementById('ts-out'); }

function tsDoInstall(){
  var b=document.getElementById('ts-install'); b.disabled=true;
  tsOut().innerHTML='<i class="bi bi-arrow-repeat"></i> Installing Tailscale… (up to a minute)';
  tsApi('install',{method:'POST'}).then(function(d){
    if(!d.success){ tsOut().innerHTML='<span class="text-danger">Install failed: '+tsEsc((d.log||'').slice(-200))+'</span>'; b.disabled=false; return; }  // nosemgrep - the log tail is tsEsc-wrapped
    tsOut().innerHTML='<span class="text-success">Installed.</span> Starting…';
    tsDoUp();
  }).catch(function(){ tsOut().innerHTML='<span class="text-danger">Install request failed.</span>'; b.disabled=false; });
}

function tsDoUp(){
  tsOut().innerHTML='<i class="bi bi-arrow-repeat"></i> Starting Tailscale…';
  tsApi('up',{method:'POST'}).then(function(d){
    if(!d.success){ tsOut().innerHTML='<span class="text-danger">'+tsEsc(d.message||'Failed')+'</span>'; return; }  // nosemgrep - tsEsc is window.escapeHtml
    if(d.connected){ tsOut().innerHTML='<span class="text-success">Connected!</span>'; setTimeout(tsRefresh,800); return; }
    tsOut().innerHTML='<div class="alert alert-info py-2 small mb-0">'  // nosemgrep - literals plus auth_url, tsEsc-wrapped in both text places and _da()-encoded in the button
      + '<strong>1.</strong> Open this link and approve this machine in your Tailscale account:<br>'
      + '<a href="'+tsEsc(d.auth_url)+'" target="_blank" style="word-break:break-all;">'+tsEsc(d.auth_url)+'</a>'
      + ' <button type="button" class="btn btn-sm btn-outline-secondary py-0"' + _da('copyText', [d.auth_url]) + '><i class="bi bi-clipboard"></i></button><br>'
      + '<strong>2.</strong> <span id="ts-wait"><i class="bi bi-hourglass-split"></i> Waiting for you to authorize…</span></div>';
    var t=setInterval(function(){ tsApi('status').then(function(s){ if(s.running){ clearInterval(t); tsRender(s); } }); }, 4000);
  }).catch(function(){ tsOut().innerHTML='<span class="text-danger">Request failed.</span>'; });
}

function tsDoServe(){
  var m=document.getElementById('ts-msg'); var b=document.getElementById('ts-serve');
  b.disabled=true; m.innerHTML='<i class="bi bi-arrow-repeat"></i> Configuring HTTPS…';
  tsApi('serve',{method:'POST'}).then(function(d){
    if(!d.success){ m.innerHTML='<span class="text-danger">'+tsEsc(d.message||'Failed')+'</span>'; b.disabled=false; return; }  // nosemgrep - tsEsc is window.escapeHtml
    tsRefresh();
  }).catch(function(){ m.innerHTML='<span class="text-danger">Request failed.</span>'; b.disabled=false; });
}

tsRefresh();
