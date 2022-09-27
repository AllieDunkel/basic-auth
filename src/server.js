'use strict';

// 3rd party requirement
const express = require('express');
const bcrypt = require('bcrypt');
const base64 = require('base-64');
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
const PORT = process.env.PORT || 3002;

// we'll use this for inclass-demo.  one big monolithic file
const DATABASE_URL =
    process.env.NODE_ENV === 'test' ? 'sqlite::memory' : 'sqlite:memory';

let options =
    process.env.NODE_ENV === 'production'
      ? {
        dialectOPtions: {
          ssl: true,
          rejectUnauthorized: false,
        },
      }
      : {};

// instantiate database
const sequelizeDatabase = new Sequelize(DATABASE_URL, options);

//allow us to access request body json
app.use(express.json());

//process FROM input and add request body
app.use(express.urlencoded({ extended: true }));

//create a Sequelize Model
const UsersModel = sequelizeDatabase.define('Users', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Attach beforecreate Hook to the userModel
UsersModel.beforeCreate((user) => {
  console.log('our user', user);
});

// Define basicAuth Middleware.
// implement on basic-auth-secured routes only. ie. the '/signin' or '/hello' route
//TODO:

async function basicAuth(req, res, next) {
  let { authorization } = req.headers;
  console.log('authorization::::', authorization);
  //confirm request header has an "authorization" property
  if (!authorization) {
    res.status(401).send('Not Authorized');
  } else {
    //parse the basic auth string
    let authString = authorization.split(' ')[1];
    console.log('authStr:', authString);

    let decodedAuthString = base64.decode(authString);
    console.log('decodedAuthString:', decodedAuthString);

    let [username, password] = decodedAuthString.split(':');
    console.log('username:', username);
    console.log('password:', password);

    // find the user in the database
    let user = await UsersModel.findOne({ where: { username } });
    console.log('user:', user);
    // IF the user exists (in database after a signup request) ...
    if (user) {
      //compare password from database to the signin password
      //note: password could also be sent from a logged in client
      let validUser = await bcrypt.compare(password, user.password);
      console.log('validUser', validUser);

      //if valid user DOES exist ...
      if (validUser) {
        //attach user to the request object
        req.user = user;
        //basicAuth middleware is done, pass request to next middleware
        next();
        //if valid user DOES NOT exist...
      } else {
        //send a "Not Authorized" error to express middleware
        next('Not Authorized');
      }
    }
  }
}

// define a signup route to Create new user in database
app.post('/signup', async (req, res, next) => {
  console.log('I am here');
  try {
    let { username, password } = req.body;
    let encryptedPassword = await bcrypt.hash(password, 5);

    let user = await UsersModel.create({
      username,
      password: encryptedPassword,
    });
    res.status(200).send(user);
  } catch (err) {
    next('signup error occurred');
  }
});

//define a signin route to Returns user object to client (confirm user auth)

app.post('/signin', basicAuth, (req, res, next) => {
  res.status(200).send(req.user);
});

// define a hello route that uses basic auth to safeguard response content

app.get('/hello', basicAuth, (req, res, next) => {
  let { name } = req.query;
  res.status(200).send(`Greetings ${name} this is now secured by Basic Auth!!!`);
});

// export app for testing, start ability to run app, and our db with ORM
module.exports = {
  server:app,
  start: () => app.listen(PORT, console.log('server is running on', PORT)),
  sequelizeDatabase,
};
