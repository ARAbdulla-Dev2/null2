const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs/promises');
const fs2 = require('fs');
const path = require('path');

require('dotenv').config();

const User = require('./models/User'); // Define the User model

const app = express();

// Middleware
app.use(express.static('assets'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());

// Set the view engine to EJS
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

const validateUserApiKey = async (req, res, next) => {
    const apiKey = req.query.apiKey || req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(401).json({ message: "API key is missing." });
    }
  
    try {
      const user = await User.findOne({ apiKey });
      if (!user) {
        return res.status(403).json({ message: "Invalid API key." });
      }
  
      // Check request limit
      if (user.requestLimit !== Infinity && user.requestsMade >= user.requestLimit) {
        return res.status(429).json({ message: "Request limit exceeded." });
      }
  
      // Increment request count
      user.requestsMade += 1;
      await user.save();
  
      // Log the request globally
      const requestsLogPath = path.join(__dirname, 'data', 'requests.json');
      const requestsData = JSON.parse(await fs.readFile(requestsLogPath, 'utf8')) || {};
      requestsData[user._id] = (requestsData[user._id] || 0) + 1;
      await fs.writeFile(requestsLogPath, JSON.stringify(requestsData, null, 2));
  
      req.user = user; // Attach user data
      next();
    } catch (error) {
      console.error("API key validation error:", error);
      res.status(500).json({ message: "An error occurred while validating the API key." });
    }
  };
  

// Database Connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Google Authentication
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://api.arabdullah.top/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = new User({
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            profilePic: profile.photos[0].value,
            apiKey: crypto.randomBytes(8).toString('hex'), // Generate a 16-character API key
          });
          await user.save();
        }
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
  
/*
  app.use(async (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
    if (req.isAuthenticated()) {
      const user = req.user;
  
      // Check if the IP is already in use by another user
      const existingUser = await User.findOne({ ipAddress: clientIp, _id: { $ne: user._id } });
      if (existingUser) {
        return res.status(403).send('This IP address is already associated with another account.');
      }
  
      // Update user's IP address
      user.ipAddress = clientIp;
      await user.save();
    }
    next();
  });
  */

// Routes

// Signup Page
app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/public/signup.html');
  });


app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
  });

   

// Google Authentication
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/signup' }),
  (req, res) => {
    if (req.user.username && req.user.phone) {
      res.redirect('/dashboard');
    } else {
      res.redirect('/ask-details');
    }
  }
);

app.post('/delete-account', async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/signup');
  
    try {
      await User.findByIdAndDelete(req.user._id);
      req.logout((err) => {
        if (err) return res.status(500).send('Failed to logout after deletion.');
        req.session.destroy(() => {
          res.clearCookie('connect.sid');
          res.redirect('/signup');
        });
      });
    } catch (error) {
      console.error('Error deleting account:', error);
      res.status(500).send('Error deleting account.');
    }
  });
  

// Ask for Details for New Users
app.get('/ask-details', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/signup');
  res.render('askDetails', { user: req.user });
});

app.post('/ask-details', async (req, res) => {
  const { username, phone } = req.body;
  const user = req.user;

  if (user) {
    user.username = username;
    user.phone = phone;
    await user.save();
    res.redirect('/dashboard');
  } else {
    res.redirect('/signup');
  }
});

      
app.post('/complete-signup', async (req, res) => {
    const { email, username, phone } = req.body;
  
    try {
      const existingUsername = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
      const existingPhone = await User.findOne({ phone: { $regex: new RegExp(`^${phone}$`, 'i') } });
  
      if (existingUsername || existingPhone) {
        return res.status(400).send('Username or phone number is already taken.');
      }
  
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).send('User not found.');
      }
  
      user.username = username;
      user.phone = phone;
  
      // Generate an API key if it doesn't exist
      if (!user.apiKey) {
        user.apiKey = crypto.randomBytes(8).toString('hex'); // 16-character alphanumeric key
      }
  
      await user.save();
      res.redirect('/dashboard');
    } catch (error) {
      console.error('Error in /complete-signup:', error);
      res.status(500).send('Internal Server Error');
    }
  });
    

// Dashboard
app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/signup');
  res.render('dashboard', { user: req.user });
});

app.post('/check-username', async (req, res) => {
    const { username } = req.body;
    const user = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
    res.json({ available: !user });
  });
  
  app.post('/check-phone', async (req, res) => {
    const { phone } = req.body;
    const user = await User.findOne({ phone: { $regex: new RegExp(`^${phone}$`, 'i') } });
    res.json({ available: !user });
  });


  app.get('/api', validateUserApiKey, async (req, res) => {
    const { plugin, query } = req.query;
  
    if (!plugin) {
      return res.status(400).json({
        status: "false",
        message: "Invalid or missing plugin.",
      });
    }
  
    try {
      const pluginPath = `./plugins/${plugin}.js`;
      const pluginModule = require(pluginPath);
  
      if (typeof pluginModule !== 'function') {
        return res.status(500).json({
          status: "false",
          message: "Plugin is not a valid function.",
        });
      }
  
      const result = await pluginModule(query);
  
      res.json({
        status: "true",
        developer: "@ARAbdulla-Dev",
        plugin,
        user: req.user.name,
        result,
      });
    } catch (error) {
      console.error(`Error in plugin ${plugin}:`, error);
      res.status(500).json({
        status: "false",
        message: `An error occurred while processing the plugin: ${error.message}`,
      });
    }
  });
  
  // Route to fetch plugins.json
app.get('/data/plugins', (req, res) => {
  fs2.readFile(path.join(__dirname, 'data', 'plugins.json'), 'utf-8', (err, data) => {
    if (err) {
      console.error('Error reading plugins.json:', err);
      return res.status(500).json({ error: 'Failed to load plugin data.' });
    }
    res.json(JSON.parse(data));
  });
});

// Route to serve docs.html
app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).send('Failed to logout');
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/signup');
    });
  });
});

// Server
app.listen(process.env.PORT, () => {
  console.log(`Server is running on http://127.0.0.1:${process.env.PORT}`);
});
