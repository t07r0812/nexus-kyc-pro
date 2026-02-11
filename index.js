     1	const express = require('express');
     2	const cors = require('cors');
     3	const dotenv = require('dotenv');
     4	const { Pool } = require('pg');
     5	const bcrypt = require('bcryptjs');
     6	const jwt = require('jsonwebtoken');
     7	const axios = require('axios');
     8	const multer = require('multer');
     9	const FormData = require('form-data');
    10	const fs = require('fs');
    11	const path = require('path');
    12	
    13	// Load environment variables
    14	dotenv.config();
    15	
    16	const app = express();
    17	const PORT = process.env.PORT || 3000;
    18	
    19	// Middleware
    20	app.use(cors());
    21	app.use(express.json());
    22	app.use(express.static('public'));
    23	
    24	// Create uploads directory
    25	const uploadsDir = path.join(__dirname, 'uploads');
    26	if (!fs.existsSync(uploadsDir)) {
    27	    fs.mkdirSync(uploadsDir, { recursive: true });
    28	}
    29	
    30	// Multer configuration
    31	const storage = multer.diskStorage({
    32	    destination: (req, file, cb) => {
    33	        cb(null, uploadsDir);
    34	    },
    35	    filename: (req, file, cb) => {
    36	        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    37	        cb(null, uniqueSuffix + '-' + file.originalname);
    38	    }
    39	});
    40	
    41	const upload = multer({ 
    42	    storage: storage,
    43	    limits: { fileSize: 10 * 1024 * 1024 },
    44	    fileFilter: (req, file, cb) => {
    45	        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf'];
    46	        if (allowedTypes.includes(file.mimetype)) {
    47	            cb(null, true);
    48	        } else {
    49	            cb(new Error('Invalid file type. Only JPEG, PNG, and PDF are allowed.'));
    50	        }
    51	    }
    52	});
    53	
    54	// Database configuration
    55	const pool = new Pool({
    56	    connectionString: process.env.DATABASE_URL,
    57	    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    58	});
    59	
    60	// Test database connection
    61	pool.connect((err, client, release) => {
    62	    if (err) {
    63	        console.error('Error connecting to database:', err);
    64	    } else {
    65	        console.log('Connected to PostgreSQL database');
    66	        release();
    67	    }
    68	});
    69	
    70	// Initialize database tables
    71	async function initDatabase() {
    72	    try {
    73	        // Users table
    74	        await pool.query(`
    75	            CREATE TABLE IF NOT EXISTS users (
    76	                id SERIAL PRIMARY KEY,
    77	                email VARCHAR(255) UNIQUE NOT NULL,
    78	                password VARCHAR(255) NOT NULL,
    79	                first_name VARCHAR(100),
    80	                last_name VARCHAR(100),
    81	                role VARCHAR(50) DEFAULT 'user',
    82	                company VARCHAR(255),
    83	                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    84	                last_login TIMESTAMP
    85	            )
    86	        `);
    87	
    88	        // Companies table
    89	        await pool.query(`
    90	            CREATE TABLE IF NOT EXISTS companies (
    91	                id SERIAL PRIMARY KEY,
    92	                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    93	                name VARCHAR(255) NOT NULL,
    94	                registration_number VARCHAR(100),
    95	                tax_id VARCHAR(100),
    96	                legal_form VARCHAR(100),
    97	                street VARCHAR(255),
    98	                city VARCHAR(100),
    99	                postal_code VARCHAR(20),
   100	                country VARCHAR(100) DEFAULT 'Deutschland',
