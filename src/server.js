// server.js
// This version includes critical security enhancements:
// 1. API Rate Limiting to prevent abuse.
// 2. Server-side input validation to ensure data integrity.

// --- Dependencies ---
const express = require('express');
const cors = require('cors');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, QueryCommand } = require("@aws-sdk/lib-dynamodb");
const { v4: uuidv4 } = require('uuid');
// ** NEW: Security-related dependencies **
const rateLimit = require('express-rate-limit');
const { body, validationResult, param } = require('express-validator');
// ** STEP 1: Import the authorization middleware from the file you created **
const authorizationMiddleware = require('./authMiddleware');

// --- Initialization ---
const app = express();
const PORT = process.env.PORT || 3001;
const TABLE_NAME = 'paypouch-subscriptions';

// --- AWS SDK Configuration ---
const dynamoDBClient = new DynamoDBClient({ region: "us-east-1" });
const docClient = DynamoDBDocumentClient.from(dynamoDBClient);

// --- Middleware ---
app.use(express.json());
app.use(cors());

// ** NEW: Rate Limiting Middleware **
// This will limit each IP address to 100 requests per 15 minutes.
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use(limiter); // Apply the rate limiting middleware to all requests

// --- API Routes with Validation ---

/**
 * Route:   POST /api/subscriptions
 * Purpose: Creates a new subscription after validating the input data.
 * Body:    Expects { userId, subscriptionName, cost }
 */
app.post(
    '/api/subscriptions',
    authorizationMiddleware, // Middleware runs before the validation and main logic
    // ** NEW: Validation rules for the request body **
    body('userId').isString().withMessage('User ID must be a string.').notEmpty().withMessage('User ID cannot be empty.'),
    body('subscriptionName').isString().isLength({ min: 1, max: 100 }).withMessage('Subscription name must be between 1 and 100 characters.'),
    body('cost').isFloat({ gt: 0 }).withMessage('Cost must be a number greater than 0.'),

    async (req, res) => {
        // ** NEW: Check for validation errors **
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        console.log('Received valid request to create a subscription...');
        const { userId, subscriptionName, cost } = req.body;

        const subscriptionId = uuidv4();
        const newSubscription = {
            userId: userId,
            subscriptionId: subscriptionId,
            subscriptionName: subscriptionName,
            cost: parseFloat(cost), // Ensure cost is a number
            createdAt: new Date().toISOString()
        };
        
        const command = new PutCommand({
            TableName: TABLE_NAME,
            Item: newSubscription,
        });

        try {
            await docClient.send(command);
            console.log('Successfully saved subscription to DynamoDB.');
            res.status(201).json({
                message: 'Subscription created successfully',
                subscription: newSubscription
            });
        } catch (error) {
            console.error("DynamoDB error:", error);
            res.status(500).json({ message: 'Failed to save subscription.', error: error.message });
        }
    }
);


/**
 * Route:   GET /api/subscriptions/:userId
 * Purpose: Retrieves all subscriptions for a given user after validating the userId.
 * Params:  Expects a userId in the URL path.
 */
app.get(
    '/api/subscriptions/:userId',
    authorizationMiddleware, // Middleware runs before the validation and main logic
    // ** NEW: Validation rule for the URL parameter **
    param('userId').isString().withMessage('User ID must be a string.').notEmpty().withMessage('User ID cannot be empty.'),

    async (req, res) => {
        // ** NEW: Check for validation errors **
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { userId } = req.params;
        console.log(`Received valid request to get subscriptions for user: ${userId}`);

        const command = new QueryCommand({
            TableName: TABLE_NAME,
            KeyConditionExpression: "userId = :uid",
            ExpressionAttributeValues: { ":uid": userId },
        });

        try {
            const { Items } = await docClient.send(command);
            console.log(`Found ${Items.length} subscriptions for user.`);
            res.status(200).json(Items);
        } catch (error) {
            console.error("DynamoDB error:", error);
            res.status(500).json({ message: 'Failed to retrieve subscriptions.', error: error.message });
        }
    }
);


// --- Server Activation ---
app.listen(PORT, () => {
    console.log(`PayPouch server is running on http://localhost:${PORT}`);
});

