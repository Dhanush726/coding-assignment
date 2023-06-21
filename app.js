// app.js

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

// Create and connect to the database
const db = new sqlite3.Database("twitterClone.db");

// Middleware to parse JSON requests
app.use(express.json());

// Secret key for JWT
const jwtSecretKey = "your-secret-key";

// Route for user registration
app.post("/register", (req, res) => {
  const { username, password, name, gender } = req.body;

  // Check if the username already exists
  db.get("SELECT * FROM user WHERE username = ?", [username], (err, row) => {
    if (err) {
      return res.status(500).send("Internal Server Error");
    }
    if (row) {
      return res.status(400).send("User already exists");
    }

    // Check password length
    if (password.length < 6) {
      return res.status(400).send("Password is too short");
    }

    // Encrypt the password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Create a new user
    db.run(
      "INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)",
      [name, username, hashedPassword, gender],
      (err) => {
        if (err) {
          return res.status(500).send("Internal Server Error");
        }
        return res.status(200).send("User created successfully");
      }
    );
  });
});

// Route for user login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Find the user in the database
  db.get("SELECT * FROM user WHERE username = ?", [username], (err, row) => {
    if (err) {
      return res.status(500).send("Internal Server Error");
    }
    if (!row) {
      return res.status(400).send("Invalid user");
    }

    // Check if the password is correct
    const isPasswordValid = bcrypt.compareSync(password, row.password);
    if (!isPasswordValid) {
      return res.status(400).send("Invalid password");
    }

    // Generate a JWT token
    const token = jwt.sign({ username }, jwtSecretKey);

    return res.send({ jwtToken: token });
  });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1]; // Split the token to remove the "Bearer " prefix

  if (!token) {
    return res.status(401).send("Invalid JWT Token");
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send("Invalid JWT Token");
    }

    req.username = decoded.username;
    next();
  });
}

// Fetch the latest tweets of people whom the user follows
app.get("/user/tweets/feed", authenticateToken, (req, res) => {
  const { username } = req;

  // Get the user ID of the authenticated user
  db.get(
    "SELECT user_id FROM user WHERE username = ?",
    [username],
    (err, row) => {
      if (err) {
        return res.status(500).send("Internal Server Error");
      }

      if (!row) {
        return res.status(401).send("Invalid User");
      }

      const userId = row.user_id;

      // Fetch the latest 4 tweets of people whom the user follows
      db.all(
        `SELECT t.tweet, u.username, t.date_time
       FROM tweet AS t
       JOIN follower AS f ON t.user_id = f.following_user_id
       JOIN user AS u ON t.user_id = u.user_id
       WHERE f.follower_user_id = ?
       ORDER BY t.date_time DESC
       LIMIT 4`,
        [userId],
        (err, rows) => {
          if (err) {
            return res.status(500).send("Internal Server Error");
          }
          return res.json(rows);
        }
      );
    }
  );
});

// Get the list of all names of people whom the user follows
app.get("/user/following", authenticateToken, (req, res) => {
  const { username } = req;

  // Get the user ID of the authenticated user
  db.get(
    "SELECT user_id FROM user WHERE username = ?",
    [username],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Internal Server Error");
      }

      if (!row) {
        return res.status(401).send("Invalid User");
      }

      const userId = row.user_id;

      // Fetch the list of names of people whom the user follows
      db.all(
        `SELECT u.name
       FROM user AS u
       JOIN follower AS f ON u.user_id = f.following_user_id
       WHERE f.follower_user_id = ?`,
        [userId],
        (err, rows) => {
          if (err) {
            console.error(err);
            return res.status(500).send("Internal Server Error");
          }

          const followingNames = rows.map((row) => row.name);
          return res.json(followingNames);
        }
      );
    }
  );
});

// Get the list of all names of people who follow the user
app.get("/user/followers", (req, res) => {
  // Check if the JWT token exists in the request headers
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send("Invalid JWT Token");
  }

  // Verify the JWT token and extract the username
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send("Invalid JWT Token");
    }

    const { username } = decoded;

    // Query the database to get the list of followers
    db.all(
      `SELECT u.name
       FROM user AS u
       JOIN follower AS f ON u.user_id = f.follower_user_id
       WHERE f.following_user_id = (SELECT user_id FROM user WHERE username = ?)`,
      [username],
      (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).send("Internal Server Error");
        }

        const followerNames = rows.map((row) => row.name);
        return res.json(followerNames);
      }
    );
  });
});

// Route for getting a specific tweet by tweet ID
app.get("/tweets/:tweetId", authenticateToken, (req, res) => {
  const { username } = req;
  const { tweetId } = req.params;

  // Check if the user is allowed to access the tweet
  db.get(
    `SELECT t.tweet, COUNT(l.like_id) AS likes, COUNT(r.reply_id) AS replies, t.date_time
     FROM tweet AS t
     LEFT JOIN like AS l ON t.tweet_id = l.tweet_id
     LEFT JOIN reply AS r ON t.tweet_id = r.tweet_id
     WHERE t.tweet_id = ? AND (t.user_id = ? OR EXISTS (
       SELECT 1
       FROM follower AS f
       WHERE f.follower_user_id = ? AND f.following_user_id = t.user_id
     ))
     GROUP BY t.tweet_id`,
    [tweetId, username, username],
    (err, row) => {
      if (err) {
        return res.status(500).send("Internal Server Error");
      }
      if (!row) {
        return res.status(401).send("Invalid Request");
      }
      return res.send(row);
    }
  );
});

// Route for getting the list of usernames who liked a specific tweet
app.get("/tweets/:tweetId/likes", authenticateToken, (req, res) => {
  const { username } = req;
  const { tweetId } = req.params;

  // Check if the user is allowed to access the tweet
  db.get(
    `SELECT 1
     FROM tweet AS t
     WHERE t.tweet_id = ? AND (t.user_id = ? OR EXISTS (
       SELECT 1
       FROM follower AS f
       WHERE f.follower_user_id = ? AND f.following_user_id = t.user_id
     ))`,
    [tweetId, username, username],
    (err, row) => {
      if (err) {
        return res.status(500).send("Internal Server Error");
      }
      if (!row) {
        return res.status(401).send("Invalid Request");
      }

      // Fetch the list of usernames who liked the tweet
      db.all(
        `SELECT u.username
         FROM user AS u
         INNER JOIN like AS l ON u.user_id = l.user_id
         WHERE l.tweet_id = ?`,
        [tweetId],
        (err, rows) => {
          if (err) {
            return res.status(500).send("Internal Server Error");
          }
          return res.send({ likes: rows.map((row) => row.username) });
        }
      );
    }
  );
});

// Route for getting the list of replies to a specific tweet
app.get("/tweets/:tweetId/replies", authenticateToken, (req, res) => {
  const { username } = req;
  const { tweetId } = req.params;

  // Check if the user is allowed to access the tweet
  db.get(
    `SELECT 1
     FROM tweet AS t
     WHERE t.tweet_id = ? AND (t.user_id = ? OR EXISTS (
       SELECT 1
       FROM follower AS f
       WHERE f.follower_user_id = ? AND f.following_user_id = t.user_id
     ))`,
    [tweetId, username, username],
    (err, row) => {
      if (err) {
        return res.status(500).send("Internal Server Error");
      }
      if (!row) {
        return res.status(401).send("Invalid Request");
      }

      // Fetch the list of replies to the tweet
      db.all(
        `SELECT u.name, r.reply
         FROM reply AS r
         INNER JOIN user AS u ON r.user_id = u.user_id
         WHERE r.tweet_id = ?`,
        [tweetId],
        (err, rows) => {
          if (err) {
            return res.status(500).send("Internal Server Error");
          }
          return res.send({ replies: rows });
        }
      );
    }
  );
});

// Get all tweets of the user
app.get("/user/tweets", (req, res) => {
  // Check if the JWT token exists in the request headers
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send("Invalid JWT Token");
  }

  // Verify the JWT token and extract the username
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send("Invalid JWT Token");
    }

    const { username } = decoded;

    // Query the database to get all tweets of the user
    db.all(
      `SELECT tweet, likes, replies, dateTime
       FROM tweet
       WHERE user_id = (SELECT user_id FROM user WHERE username = ?)`,
      [username],
      (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).send("Internal Server Error");
        }

        return res.json(rows);
      }
    );
  });
});

// Route for creating a tweet
app.post("/user/tweets", authenticateToken, (req, res) => {
  const { username } = req;
  const { tweet } = req.body;

  // Create a new tweet
  db.run(
    "INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, (SELECT user_id FROM user WHERE username = ?), datetime())",
    [tweet, username],
    (err) => {
      if (err) {
        return res.status(500).send("Internal Server Error");
      }
      return res.send("Created a Tweet");
    }
  );
});

// Delete a tweet
app.delete("/tweets/:tweetId/", (req, res) => {
  // Check if the JWT token exists in the request headers
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send("Invalid JWT Token");
  }

  // Verify the JWT token and extract the username
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send("Invalid JWT Token");
    }

    const { username } = decoded;
    const tweetId = req.params.tweetId;

    // Delete the tweet from the database
    db.run(
      `DELETE FROM tweet
       WHERE tweet_id = ?
         AND user_id = (SELECT user_id FROM user WHERE username = ?)`,
      [tweetId, username],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).send("Internal Server Error");
        }

        if (this.changes === 0) {
          // No rows were affected, indicating the tweet does not belong to the user
          return res.status(401).send("Invalid Request");
        }

        // Tweet deleted successfully
        return res.send("Tweet Removed");
      }
    );
  });
});

// Route for liking a tweet
app.post("/tweets/:tweetId/likes", authenticateToken, (req, res) => {
  const { username } = req;
  const { tweetId } = req.params;

  // Check if the user is allowed to like the tweet
  db.get(
    `SELECT 1
     FROM tweet AS t
     WHERE t.tweet_id = ? AND EXISTS (
       SELECT 1
       FROM follower AS f
       WHERE f.follower_user_id = ? AND f.following_user_id = t.user_id
     )`,
    [tweetId, username],
    (err, row) => {
      if (err) {
        return res.status(500).send("Internal Server Error");
      }
      if (!row) {
        return res.status(401).send("Invalid Request");
      }

      // Like the tweet
      db.run(
        "INSERT INTO like (tweet_id, user_id) VALUES (?, (SELECT user_id FROM user WHERE username = ?))",
        [tweetId, username],
        (err) => {
          if (err) {
            return res.status(500).send("Internal Server Error");
          }
          return res.send("Liked the Tweet");
        }
      );
    }
  );
});

// Route for replying to a tweet
app.post("/tweets/:tweetId/replies", authenticateToken, (req, res) => {
  const { username } = req;
  const { tweetId } = req.params;
  const { reply } = req.body;

  // Check if the user is allowed to reply to the tweet
  db.get(
    `SELECT 1
     FROM tweet AS t
     WHERE t.tweet_id = ? AND EXISTS (
       SELECT 1
       FROM follower AS f
       WHERE f.follower_user_id = ? AND f.following_user_id = t.user_id
     )`,
    [tweetId, username],
    (err, row) => {
      if (err) {
        return res.status(500).send("Internal Server Error");
      }
      if (!row) {
        return res.status(401).send("Invalid Request");
      }

      // Reply to the tweet
      db.run(
        "INSERT INTO reply (tweet_id, user_id, reply) VALUES (?, (SELECT user_id FROM user WHERE username = ?), ?)",
        [tweetId, username, reply],
        (err) => {
          if (err) {
            return res.status(500).send("Internal Server Error");
          }
          return res.send("Replied to the Tweet");
        }
      );
    }
  );
});

// Start the server
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});

module.exports = app;
