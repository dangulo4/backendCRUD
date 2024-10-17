require('dotenv').config();
const jwt = require('jsonwebtoken');
const marked = require('marked');
const sanitizeHTML = require('sanitize-html');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const express = require('express');
const { redirect } = require('express/lib/response');
const db = require('better-sqlite3')('ourApp.db');
db.pragma('journal_mode = WAL');

// database setup
const createTables = db.transaction(() => {
  db.prepare(
    `
  CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username STRING NOT NULL UNIQUE,
  password STRING NOT NULL
  )
  `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
    )
    `
  ).run();
});

createTables();
// database setip ends
const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(cookieParser());
app.use(function (req, res, next) {
  // marked function
  res.locals.filterUserHTML = function (content) {
    return sanitizeHTML(marked.parse(content), {
      allowedTags: ['p', 'br', 'ul', 'li', 'ol', 'strong', 'bold', 'i', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
      allowedAttributes: {},
    });
  };
  res.locals.errors = [];

  // try to decode incoming cookie
  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }
  res.locals.user = req.user;
  console.log(req.user);
  next();
});
// homepage feature, check if user is logged in
app.get('/', (req, res) => {
  if (req.user) {
    const postsStatement = db.prepare('SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC');
    const posts = postsStatement.all(req.user.userid);
    return res.render('dashboard', { posts });
  }
  res.render('homepage');
});
//login feature
app.get('/login', (req, res) => {
  res.render('login');
});
// logout feature
app.get('/logout', (req, res) => {
  res.clearCookie('ourSimpleApp');
  res.redirect('/');
});
// login feature
app.post('/login', (req, res) => {
  let errors = [];

  if (typeof req.body.username !== 'string') req.body.username = '';
  if (typeof req.body.password !== 'string') req.body.password = '';

  if (req.body.username.trim() == '') errors = ['Invalid username/password'];
  if (req.body.password == '') errors = ['Invalid username/password'];

  if (errors.length) {
    return res.render('login', { errors });
  }
  // lookup username
  const selectUser = db.prepare('SELECT * FROM users WHERE USERNAME = ?');
  const getUser = selectUser.get(req.body.username);

  if (!getUser) {
    errors = ['username/password does not exist'];
    return res.render('login', { errors });
  }
  const matchUser = bcrypt.compareSync(req.body.password, getUser.password);
  if (!matchUser) {
    errors = ['Invalid username / password'];
    return res.render('login', { errors });
  }
  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      slapback: 'delay',
      userid: getUser.id,
      username: getUser.username,
    },
    process.env.JWTSECRET
  );

  res.cookie('ourSimpleApp', ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24,
  });
  res.redirect('/');
});

function checkLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect('/');
}

app.get('/create-post', checkLoggedIn, (req, res) => {
  res.render('create-post');
});

function validatePost(req) {
  const errors = [];

  if (typeof req.body.title !== 'string') req.body.title = '';
  if (typeof req.body.body !== 'string') req.body.body = '';

  if (!req.body.title) errors.push('You must provide a title');
  if (!req.body.body) errors.push('You must provide content');

  // trim sanitize or strip out HTML
  req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} });
  req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} });

  return errors;
}

// click on edit post
app.get('/edit-post/:id', checkLoggedIn, (req, res) => {
  // look up post to edit
  const statement = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = statement.get(req.params.id);
  // if post does not exist
  if (!post) {
    return res.redirect('/');
  }
  // if not the author, redirect to homepage
  if (post.authorid !== req.user.userid) {
    return res.redirect('/');
  }

  // render edit post template
  res.render('edit-post', { post });
});
// edit the post
app.post('/edit-post/:id', checkLoggedIn, (req, res) => {
  // look up post
  const statement = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = statement.get(req.params.id);
  // if post does not exist
  if (!post) {
    return res.redirect('/');
  }
  // not the author, redirec to homepage
  if (post.authorid !== req.user.userid) {
    return res.redirect('/');
  }

  const errors = validatePost(req);
  if (errors.length) {
    return res.render('edit-post', { errors });
  }

  const updateStatement = db.prepare('UPDATE posts SET title = ?, body = ? WHERE id = ?');
  updateStatement.run(req.body.title, req.body.body, req.params.id);
  // redirect to the post that was edited
  res.redirect(`/post/${req.params.id}`);
});

app.post('/delete-post/:id', checkLoggedIn, (req, res) => {
  // look up post
  const statement = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = statement.get(req.params.id);
  // if post does not exist
  if (!post) {
    return res.redirect('/');
  }
  // not the author, redirec to homepage
  if (post.authorid !== req.user.userid) {
    return res.redirect('/');
  }

  const deleteStatement = db.prepare('DELETE FROM posts where id =?');
  deleteStatement.run(req.params.id);

  res.redirect('/');
});

// get all posts
app.get('/post/:id', (req, res) => {
  const statement = db.prepare(
    'SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?'
  );
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect('/');
  }

  const isAuthor = post.authorid === req.user.userid;
  res.render('single-post', { post, isAuthor });
});

app.post('/create-post', checkLoggedIn, (req, res) => {
  const errors = validatePost(req);

  // check to see if there are errors
  if (errors.length) {
    return res.render('create-post', { errors });
  }

  // save into database post table
  const ourStatement = db.prepare('INSERT INTO posts (title, body, authorid, createdDate) VALUES (?,?,?,?)');
  const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString());

  const getPostStatement = db.prepare('SELECT * FROM posts WHERE ROWID = ?');
  const realPost = getPostStatement.get(result.lastInsertRowid);

  res.redirect(`/post/${realPost.id}`);
});

//register feature
app.post('/register', (req, res) => {
  const errors = [];

  if (typeof req.body.username !== 'string') req.body.username = '';
  if (typeof req.body.password !== 'string') req.body.password = '';

  req.body.username = req.body.username.trim();

  if (!req.body.username) errors.push('You must provide a username.');
  if (req.body.username && req.body.username.length < 3) errors.push('Username must be at least 3 characters.');
  if (req.body.username && req.body.username.length > 10) errors.push('Username cannot exceed 10 characters.');
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push('Username can only include letters and numbers');

  // check if username exists
  const getUsername = db.prepare('SELECT * FROM users WHERE username =?');
  const checkUsername = getUsername.get(req.body.username);

  if (checkUsername) errors.push('That username already exists in the database');

  if (!req.body.password) errors.push('You must provide a password.');
  if (req.body.password && req.body.password.length < 5) errors.push('Password must be at least 5 characters.');
  if (req.body.password && req.body.password.length > 30) errors.push('Password cannot exceed 30 characters.');

  if (errors.length) {
    return res.render('homepage', { errors });
  }

  // save the new user into a database
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);
  const ourStatement = db.prepare('INSERT INTO users (username, password) VALUES (?,?)');
  const result = ourStatement.run(req.body.username, req.body.password);

  // log the user in by providing a cookie
  const lookupStatement = db.prepare('SELECT * FROM users where ROWID = ?');
  const ourUser = lookupStatement.get(result.lastInsertRowid);

  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      slapback: 'delay',
      userid: ourUser.id,
      username: ourUser.username,
    },
    process.env.JWTSECRET
  );

  res.cookie('ourSimpleApp', ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24,
  });
  res.redirect('/');
});

app.listen(3000);
