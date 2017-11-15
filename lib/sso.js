'use strict';

// Load modules

const Crypto = require('crypto');
const Fs = require('fs');
const Qs = require('querystring');
const Boom = require('boom');
const Cryptiles = require('cryptiles');
const Hoek = require('hoek');
const Wreck = require('wreck');


const internals = {
  defaults: {
    url: '',
    keyId: '',
    keyPath: '',
    cookieName: 'sso',
    apiBaseUrl: '',
    permissions: ''
  }
};

module.exports = class SSO {
  constructor (options) {
    this._settings = Hoek.applyToDefaults(internals.defaults, options);
    this._settings.privateKey = this._settings.privateKey || Fs.readFileSync(this._settings.keyPath);
    this._wreck = Wreck.defaults({ baseUrl: this._settings.apiBaseUrl, json: true, rejectUnauthorized: false });
  }

  async _authenticate (request, reply) {
    const protocol = request.connection.info.protocol;
    if (protocol !== 'https' && this._settings.isSecure) {
      return reply(Boom.internal('Invalid setting  - isSecure must be set to false for non-https server'));
    }

    let state = request.state[this._settings.cookieName];

    // We either have a token coming in from a redirect from SSO
    if (request.query.token && !state) {
      try {
        const token = request.query.token;
        const profile = this._settings.apiBaseUrl ? await this.getProfile(token) : {};
        state = { token, profile };
        reply.state(this._settings.cookieName, state);
      } catch (ex) {
        console.error(ex);
      }
    }

    if (!state) {
      const options = {
        url: this._settings.url,
        privateKey: this._settings.privateKey,
        keyId: this._settings.keyId,
        returnUrl: `${protocol}://${request.info.host}${request.url.path}`
      };

      const ssoUrl = internals.getSsoUrl(options);
      return reply.redirect(ssoUrl);
    }

    return reply.continue({ credentials: state });
  }

  async getProfile (token) {
    const now = new Date().toUTCString();
    const signer = Crypto.createSign('sha256');
    signer.update(now);
    const signature = signer.sign(this._settings.privateKey, 'base64');

    const options = {
      headers: {
        Accept: 'application/json',
        'x-api-version': '~8',
        Date: now,
        Authorization: `Signature keyId="${this._settings.keyId}",algorithm="rsa-sha256" ${signature}`,
        'X-Auth-Token': token
      }
    };

    try {
      const { payload } = await this._wreck.get('/my', options);
      return payload;
    } catch (ex) {
      console.log(ex.data.payload.toString());
    }
  }

  scheme () {
    return {
      authenticate: (request, reply) => {
        this._authenticate(request, reply);
      }
    };
  }
};


internals.getSsoUrl = function (options) {
  const signer = Crypto.createSign('sha256');
  const query = Qs.stringify({
    cid: '',
    company: '',
    country: '',
    email: '',
    firstName: '',
    keyid: options.keyId,
    lastName: '',
    nonce: Cryptiles.randomString(7),
    now: new Date().toUTCString(),
    permissions: JSON.stringify(options.permissions || {}),
    returnto: options.returnUrl,
    state: ''
  });
  const url = `${options.url}?${query}`;

  signer.update(encodeURIComponent(url.toString()));
  const signature = signer.sign(options.privateKey, 'base64');

  return `${url}&sig=${encodeURIComponent(signature)}`;
};
