// Front-channel logout page: give the hidden iframes time to load, then continue to the landing page.
(function () {
	var script = document.currentScript;
	var targetURI = (script && script.getAttribute('data-redirect-uri')) || '/login';
	var executed = false;

	function triggerRedirect() {
		if (!executed) {
			executed = true;
			window.location.href = targetURI;
		}
	}

	// Unconditional safety net: redirect even when a client iframe fails, blocks or times out.
	var redirectTimeout = window.setTimeout(triggerRedirect, 2000);

	// When every iframe has loaded, redirect sooner after a short visual grace period.
	window.addEventListener('load', function () {
		window.clearTimeout(redirectTimeout);
		window.setTimeout(triggerRedirect, 500);
	});
})();
