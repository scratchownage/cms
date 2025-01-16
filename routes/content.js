const express = require('express');
const { body, validationResult } = require('express-validator');
const pool = require('../db');
const authMiddleware = require('../middleware/authMiddleware');
const roleMiddleware = require('../middleware/roleMiddleware');
const router = express.Router();

// Create a new post
router.post(
  '/',
  authMiddleware,
  [
    body('title').isString().notEmpty(),
    body('content').isString().notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, content } = req.body;

    try {
      const conn = await pool.getConnection();
      await conn.query(
        'INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
        [title, content, req.user.id]
      );


      res.status(201).json({ message: 'Post created successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Error creating post', error });
    }finally {
        if (conn) conn.release(); // Ensure the connection is released
    }
  }
);

// Get all posts
router.get('/', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const posts = await conn.query('SELECT * FROM posts');

    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching posts', error });
  } finally {
    if (conn) conn.release(); // Ensure the connection is released
  }
});

// Get a single post by ID
router.get('/:id', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [post] = await conn.query('SELECT * FROM posts WHERE id = ?', [req.params.id]);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    res.json(post);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching post', error });
  }finally {
    if (conn) conn.release(); // Ensure the connection is released
  }
});

// Update a post
router.put(
  '/:id',
  authMiddleware,
  [
    body('title').optional().isString().notEmpty(),
    body('content').optional().isString().notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, content } = req.body;

    try {
      const conn = await pool.getConnection();
      const [post] = await conn.query('SELECT * FROM posts WHERE id = ?', [req.params.id]);

      if (!post) {
        return res.status(404).json({ message: 'Post not found' });
      }

      if (post.author_id !== req.user.id) {
        return res.status(403).json({ message: 'You are not authorized to update this post' });
      }

      await conn.query(
        'UPDATE posts SET title = COALESCE(?, title), content = COALESCE(?, content) WHERE id = ?',
        [title, content, req.params.id]
      );

      res.json({ message: 'Post updated successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Error updating post', error });
    } finally {
        if (conn) conn.release(); // Ensure the connection is released
    }
  }
);

// Only admins can delete posts
router.delete('/:id', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [post] = await conn.query('SELECT * FROM posts WHERE id = ?', [req.params.id]);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    await conn.query('DELETE FROM posts WHERE id = ?', [req.params.id]);

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting post', error });
  } finally {
    if (conn) conn.release(); // Ensure the connection is released
  }
});


module.exports = router;
