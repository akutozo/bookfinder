const jwt = require('jsonwebtoken');

// set token secret and expiration date
const secret = 'mysecretsshhhhh';
const expiration = '60h';

module.exports = {
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };

    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
  
  authMiddleware: function ({req}) {
    // allows token to be sent via  req.query or headers
    let token = req.body.token || req.query.token || req.headers.authorization;
    // separate "Bearer" from "<tokenvalue>"
    if (req.headers.authorization) {
      token = token
      .split(' ')
      .pop()
      .trim();
    }
    // If no token, reject
    if (!token) {
      return req;
    }
    // Attach user data to the request object
    try {
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      req.user = data;
      //If this fails, then
    } catch {
      console.log('Invalid token');
    }
    // finally, return the updated request
    return req;
  },
};