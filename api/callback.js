module.exports = async (req, res) => {
  const clientId = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    res.status(500).send('OAuth credentials not configured on the server.');
    return;
  }

  const { code, state } = req.query || {};
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/oauth_state=([^;]+)/);
  const cookieState = match ? match[1] : null;

  if (!code || !state || state !== cookieState) {
    res.status(400).send('Invalid OAuth state. Please try again.');
    return;
  }

  try {
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'date-album-cms',
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
      }),
    });

    const data = await tokenResp.json();

    if (data.error || !data.access_token) {
      res.status(400).send('OAuth error: ' + (data.error_description || data.error || 'no token'));
      return;
    }

    const content = JSON.stringify({ token: data.access_token, provider: 'github' });
    const escaped = content.replace(/"/g, '\\"');

    const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>인증 중…</title></head>
<body>
<p>인증 완료! 창이 닫히지 않으면 수동으로 닫아주세요.</p>
<script>
(function() {
  var receivedOrigin = null;
  function receiveMessage(e) {
    if (!receivedOrigin) {
      receivedOrigin = e.origin;
      window.opener.postMessage(
        'authorization:github:success:${escaped}',
        e.origin
      );
    }
  }
  window.addEventListener('message', receiveMessage, false);
  window.opener && window.opener.postMessage('authorizing:github', '*');
})();
</script>
</body>
</html>`;

    // Clear state cookie
    res.setHeader('Set-Cookie', 'oauth_state=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(html);
  } catch (err) {
    res.status(500).send('OAuth exception: ' + (err.message || String(err)));
  }
};
