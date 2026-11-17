// Elements that start hidden, under a policy that refuses style="" attributes (style-src-attr 'none').
//
// A template marks such an element with data-start-hidden instead of style="display:none".
// panel.css hides [data-start-hidden] from the first paint; this script, loaded before panel.js and
// every page script, turns each mark into el.style.display = 'none' (set through the CSSOM, which
// the policy allows) and drops the attribute. The element then ends up exactly as the old attribute
// left it, so every page script that shows it with el.style.display = '' or tests
// el.style.display === 'none' keeps working unchanged.
//
// window.applyStartHidden(root) does the same for markup put in after load (a section re-rendered
// from a fresh copy of the page): every mark under root, root included.
(function(){
  function applyStartHidden(root){
    if (!root) return;
    var marked = Array.prototype.slice.call(root.querySelectorAll('[data-start-hidden]'));
    if (root.hasAttribute && root.hasAttribute('data-start-hidden')) marked.unshift(root);
    for (var i = 0; i < marked.length; i++) {
      marked[i].style.display = 'none';
      marked[i].removeAttribute('data-start-hidden');
    }
  }
  window.applyStartHidden = applyStartHidden;
  applyStartHidden(document);
})();
