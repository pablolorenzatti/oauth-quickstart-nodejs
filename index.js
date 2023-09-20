require('dotenv').config();
const express = require('express');
const request = require('request-promise-native');
const NodeCache = require('node-cache');
const session = require('express-session');
const opn = require('open');
const app = express();

const PORT = process.env.PORT || 3000;

const refreshTokenStore = {};
const accessTokenCache = new NodeCache({ deleteOnExpire: true });

if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.SESSION_SECRET) {
    throw new Error('Missing CLIENT_ID, CLIENT_SECRET, or SESSION_SECRET environment variable.');
}

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;

let SCOPES = ['crm.objects.contacts.read'];
if (process.env.SCOPE) {
    SCOPES = (process.env.SCOPE.split(/ |, ?|%20/)).join(' ');
}

const REDIRECT_URI = `http://localhost:${PORT}/oauth-callback`;

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

app.use(express.json()); // Para parsear el cuerpo de las solicitudes POST

const authUrl =
  'https://app.hubspot.com/oauth/authorize' +
  `?client_id=${encodeURIComponent(CLIENT_ID)}` +
  `&scope=${encodeURIComponent(SCOPES)}` +
  `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;

app.get('/install', (req, res) => {
  res.redirect(authUrl);
});

app.get('/oauth-callback', async (req, res) => {
  if (req.query.code) {
    const authCodeProof = {
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code: req.query.code,
    };

    const token = await exchangeForTokens(req.sessionID, authCodeProof);
    if (token.message) {
      return res.redirect(`/error?msg=${token.message}`);
    }

    res.redirect(`/`);
  }
});

const exchangeForTokens = async (userId, exchangeProof) => {
  try {
    const responseBody = await request.post('https://api.hubapi.com/oauth/v1/token', {
      form: exchangeProof
    });
    const tokens = JSON.parse(responseBody);
    refreshTokenStore[userId] = tokens.refresh_token;
    accessTokenCache.set(userId, tokens.access_token, Math.round(tokens.expires_in * 0.75));
    return tokens.access_token;
  } catch (e) {
    console.error(`Error exchanging ${exchangeProof.grant_type} for access token`);
    return JSON.parse(e.response.body);
  }
};

const refreshAccessToken = async (userId) => {
  const refreshTokenProof = {
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    refresh_token: refreshTokenStore[userId],
  };
  return await exchangeForTokens(userId, refreshTokenProof);
};

const getAccessToken = async (userId) => {
  if (!accessTokenCache.get(userId)) {
    console.log('Refreshing expired access token');
    await refreshAccessToken(userId);
  }
  return accessTokenCache.get(userId);
};

const isAuthorized = (userId) => {
  return refreshTokenStore[userId] ? true : false;
};

const getContact = async (accessToken) => {
  try {
    const headers = {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    };
    const result = await request.get('https://api.hubapi.com/contacts/v1/lists/all/contacts/all?count=1', {
      headers: headers
    });
    return JSON.parse(result).contacts[0];
  } catch (e) {
    console.error('Unable to retrieve contact');
    return JSON.parse(e.response.body);
  }
};

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.write(`<h2>HubSpot OAuth 2.0 Quickstart App</h2>`);
  if (isAuthorized(req.sessionID)) {
    res.write(`<p>Aplicación instalada correctamente</p>`);
    console.log(SESSION_SECRET);
  } else {
    res.write(`<a href="/install"><h3>Install the app</h3></a>`);
  }
  res.end();
});

app.get('/error', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.write(`<h4>Error: ${req.query.msg}</h4>`);
  res.end();
});

app.post('/webhook', (req, res) => {
  const payload = req.body;
  console.log('Received webhook payload:', payload);
  
  if (payload && payload.eventType) {
      switch (payload.eventType) {
          case 'contact_created':
              console.log('A new contact was created:', payload.contact);
              break;
          case 'contact_updated':
              console.log('A contact was updated:', payload.contact);
              break;
          default:
              console.log('Unknown event type:', payload.eventType);
      }
  }

  res.status(200).send('Webhook received');
});

app.listen(PORT, () => console.log(`Starting your app on http://localhost:${PORT}`));
opn(`http://localhost:${PORT}`);
