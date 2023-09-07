// JWT flow:
// 1. Create consent URI and obtain user consent.
// 2. Construct JWT using the IK and User ID, scope, RSA public and private key.
// 3. Send POST containing the JWT to DS_AUTH_SERVER to get access token.
// 4. Using the access token, send a POST to get the user's base URI (account_id + base_uri).
// 5. Now you can use the access token and base URI to make API calls.
// When the access token expires, create a new JWT and request a new access token.
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
const eSignSdk = require('docusign-esign');
const fs = require('fs'); // Used to parse RSA key
const dayjs = require('dayjs'); // Used to set and determine a token's expiration date
const oAuth = eSignSdk.ApiClient.OAuth;
const restApi = eSignSdk.ApiClient.RestApi;

// Constants
const rsaKey = fs.readFileSync('./private.key');
// const rsaKey = "MIIEowIBAAKCAQEApSEa/ySsSSU9n8Q7rc0BsXVnl9hvPdG1zqNZtykRXTOvWI2wkSIOEYkr86I66Dy6VqdV/jsoBFXGf7bQL+i127Cdhm/2grefmFPgkxyE6GIcVOHphcyah0NGErqpUpAvk2mJ1qUOlH46S73/wzv5sZm/M6s+JFd0nNIpNfNkq1IqF5ViidT3sqlWonpyVVVRW+CUlv3dRD9c8zvf5abIiJsoZ1o41E+vn8jVxq7l4HjJ19u3yk8RPk1BZB5DQSM3S+pj5o4X39aFpiI72zCNz99WtepDhNlLE4av1wIq2rjLUBqMmEhydX1JMB/9zsfHMN6xridtuhikhFfR+ZHDIwIDAQABAoIBADluFx6PmZ/i5NjQ/dSHjUQzyfCkpKPCcNHKPCSYkuJwXFaXCMahKnVs2K1mSciFfmUu05iU6GkBkATRBvzymXUrqs2b2QdDZ60p1twzOgI8RRA8deRD8aaDfjZ7VvJRFUrWlMrjIvwAHrRDA1XaYRAkobwNnZI0HGmCKjUKToPKgw/bG8yCRjuH13FJ5MNvFENJ9pOCFDWaHIBrATFerTq6SWrxYVc07/ac8QlMnUWlN1riC5IZnDN9kqEd8YUKHTMZoj7CvZuA6bHeErIOLj7skbAtUfgFl5rrxUGRheVHV0oPlfCH+AqqOfb/yohOAUfDmBgay65qcfDdj8LNEnECgYEA4ji55MWk6jvRtKNeWtWkq3SKKpzzGYpHEaGnxK94tLfcu73pzQLjAhlck6zzAtGJkCsZX3BtvPI9RAKnVMD6sJLo8vWhA5bJIYMHbuw9xp7mdpwJRwqCHfj8vF7+CQXTGaBb//XbhRgPMgFgOW1x21BLmNQYzImLAIVlhccx69sCgYEAut2tGQYgi3Yq51Dk1QbodfxiBIRicOLnuf/Ucd6tO+KKPb7IAzk7/L78Yo6Rb8Zt9jS8EqWLfqCpKfNsRupSnorVsMbRvNKh7970VmT+NVlOf2Orekc99zKmEqHphPxW9SNz7VkHTylyk3qzCSwUuiKsah1+D1iUvCPhnJ8hjFkCgYEA4Yf+REaLAH68teM9eT+PWOPpr0wjzG2gJsLMWHk71KeNJ5rRkXL0UK5qLkv5RfESvSlKtWyH6xxx2fDvU77E7u630Sjy6noUcRWJfpuFhxP53Xv4f9vJFwqZJU9q4iHtcJn/vnIk9U6kL41Rmk8zeJtXkri5NIlXjCBxs2qAqYsCgYBoCRjhELc3zd9PD4uHSqRLY+sSRr4jyUBoHpWhm+7oo1SB0eC7YrcSHSaYnHU+PMRlybBX1VDXfA0SbRMAXF8JI5SbKeYFcWN1D7ULEIkzHHiGlfAXUOif4tPxFbHUN0UWj9lv8BwQp6vBjhN1bNRRWRKStb7EPnX4VSW7tCDSaQKBgEGHNQVSdKM8GhhQg97Hfw+wv3NB95Kdx1gVHuvSNWsL0ESRoVhe6g2PvSnP5/i3SdT6iOYG0I5uvJcOpabvjTTp+KC8Jf/y8LTzE6nIgGIfiTnKTsqLifYBPtWyBaegWNvWTj10KIwcEUXCSufiP9rEuGOQbC5otWAt5r1XALWz";
const jwtLifeSec = 60 * 60; // Request lifetime of JWT token is 60 minutes
const scopes = 'signature';

// For production environment, change "DEMO" to "PRODUCTION"
const basePath = restApi.BasePath.DEMO; // https://demo.docusign.net/restapi
const oAuthBasePath = oAuth.BasePath.DEMO; // account-d.docusign.com

/**
 * Creates and sends a JWT token using the integration key, user ID, scopes and RSA key.
 * Then stores the returned access token and expiration date.
 */
const getToken = async (req) => {
  console.log('getToken called');
  // Get API client and set the base paths
  let eSignApi = new eSignSdk.ApiClient();
  console.log('eSignApi', eSignApi);
  console.log('oAuthBasePath', oAuthBasePath); 

  // eSignApi.setOAuthBasePath(oAuthBasePath);
  // console.log('eSignApi', eSignApi);
  // Request a JWT token
  let results;

  console.log('process.env.INTEGRATION_KEY', process.env.INTEGRATION_KEY);
  console.log('process.env.USER_ID', process.env.USER_ID);
  console.log('rsaKey', rsaKey);
  console.log('scopes', scopes);
  console.log('jwtLifeSec', jwtLifeSec);
  results = await eSignApi.requestJWTUserToken(
    process.env.INTEGRATION_KEY,
    process.env.USER_ID,
    scopes,
    rsaKey,
    jwtLifeSec
  );
  console.log('results', results);
  // Save the access token and the expiration timestamp
  const expiresAt = dayjs().add(results.body.expires_in, 's'); // TODO: subtract tokenReplaceMin?
  console.log('getToken expiresAt', expiresAt);
  req.session.accessToken = results.body.access_token;
  console.log('getToken results.body.access_token', results.body.access_token);

  req.session.tokenExpirationTimestamp = expiresAt;
};

/**
 * Checks to see that the current access token is still valid, and if not,
 * updates the token.
 * Must be called before every DocuSign API call.
 */
const checkToken = async (req) => {
  try {
    const noToken =
        !req.session.accessToken || !req.session.tokenExpirationTimestamp,
      currentTime = dayjs(),
      bufferTime = 1; // One minute buffer time
    console.log('checkToken noToken', noToken);
    // Check to see if we have a token or if the token is expired
    let needToken =
      noToken ||
      dayjs(req.session.tokenExpirationTimestamp)
        .subtract(bufferTime, 'm')
        .isBefore(currentTime);
        console.log('checkToken needToken', needToken);
    // Update the token if needed
    if (needToken) {
      await getToken(req);
    }
  } catch (error) {
    if (
      error.response.body.error &&
      error.response.body.error === 'consent_required'
    ) {
      throw new Error('Consent required');
    } else {
      throw error;
    }
  }
};

/**
 * Gets the account ID, account name, and base path of the user using the access token.
 */
const getUserInfo = async (req) => {
  // Get API client
  const eSignApi = new eSignSdk.ApiClient(),
    targetAccountId = process.env.targetAccountId,
    baseUriSuffix = '/restapi';
  eSignApi.setOAuthBasePath(oAuthBasePath);

  // Get user info using access token
  const results = await eSignApi.getUserInfo(req.session.accessToken);

  let accountInfo;
  if (!Boolean(targetAccountId)) {
    // Find the default account
    accountInfo = results.accounts.find(
      (account) => account.isDefault === 'true'
    );
  } else {
    // Find the matching account
    accountInfo = results.accounts.find(
      (account) => account.accountId == targetAccountId
    );
  }
  if (typeof accountInfo === 'undefined') {
    throw new Error(`Target account ${targetAccountId} not found!`);
  }

  // Save user information in session.
  req.session.accountId = accountInfo.accountId;
  req.session.basePath = accountInfo.baseUri + baseUriSuffix;
};

/**
 * First checks if there is already a valid access token, updates it if it's expired,
 * then gets some user info. If the user has never provided consent, then they are
 * redirected to a login screen.
 */
const login = async (req, res, next) => {
  console.log('login req', req.cookies);
  try {
    // As long as the user has attempted to login before, they have either successfully
    // logged in or was redirected to the consent URL and then redirected back to the
    // app. Only set the user to logged out if an unknown error occurred during the
    // login process.
    req.session.isLoggedIn = true;
    await checkToken(req);
    await getUserInfo(req);
    res.status(200).send('Successfully logged in.');
  } catch (error) {
    // User has not provided consent yet, send the redirect URL to user.
    if (error.message === 'Consent required') {
      let consent_scopes = scopes + '%20impersonation',
        consent_url =
          `${process.env.DS_OAUTH_SERVER}/oauth/auth?response_type=code&` +
          `scope=${consent_scopes}&client_id=${process.env.INTEGRATION_KEY}&` +
          `redirect_uri=${process.env.REDIRECT_URI_HOME}`;

      res.status(210).send(consent_url);
    } else {
      req.session.isLoggedIn = false;
      next(error);
    }
  }
};

/**
 * Logs the user out by destroying the session.
 */
const logout = (req, res) => {
  req.session = null;
  console.log('Successfully logged out!');
  res.status(200).send('Success: you have logged out');
};

/**
 * Sends back "true" if the user is logged in, false otherwise.
 */
const isLoggedIn = (req, res) => {
  let isLoggedIn;
  if (req.session.isLoggedIn === undefined) {
    isLoggedIn = false;
  } else {
    isLoggedIn = req.session.isLoggedIn;
  }

  res.status(200).send(isLoggedIn);
};

module.exports = {
  checkToken,
  login,
  logout,
  isLoggedIn,
};
