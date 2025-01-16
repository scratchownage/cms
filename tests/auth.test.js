const request = require('supertest');
const app = require('../app');
const pool = require('../db');
let conn;

beforeAll(async () => {
  // Initialize connection pool or perform other setup steps here
  conn = await pool.getConnection();
});

afterAll(async () => {
  // Close the connection pool explicitly
  if (conn) await conn.release(); // Close the single connection if it's still open
  if (pool) await pool.end(); // Close the entire pool
});


describe('POST /login', () => {
  it('should login successfully and return a token', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'password123' })
      .set('Content-Type', 'application/json');

    console.log('Response body:', res.body); // Log the response for debugging

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
  });
});

describe('GET /admin', () => {
  it('should return 403 for non-admin users', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'user', password: 'password123' }); // Non-admin user

    // Log the response for debugging
    console.log('Login Response body:', loginRes.body);

    const token = loginRes.body.accessToken;

    const res = await request(app)
      .get('/api/auth/admin')
      .set('Authorization', `Bearer ${token}`);

    // Log the response body for debugging
    console.log('Admin Access Response body:', res.body);

    // Check if the status is 403 (forbidden)
    expect(res.status).toBe(403);
  });
});

// Optional cleanup (if required)
afterAll(async () => {
  // Add cleanup logic here if you're adding test users, etc.
});
