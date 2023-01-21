const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const moment = require("moment");

const generatePassword = async (password) => {
  const salt = await bcrypt.genSalt(15);
  const pass = await bcrypt.hash(password, salt);
  return pass;
};

const generateJWT = (account) => {
  let jwtSecretKey = process.env.JWT_SECRET_KEY;
  let data = {
    time: moment.now().valueOf(),
    accountId: account.account_id,
    username: account.username
  };

  const token = jwt.sign(data, jwtSecretKey);
  return token;
};

const verifyJWT = async (token) => {
  let jwtSecretKey = process.env.JWT_SECRET_KEY;
  const verified = jwt.verify(token, jwtSecretKey);
  if (verified) return verified;
  else return null;
};

module.exports = {
  generatePassword,
  generateJWT,
  verifyJWT,
};
