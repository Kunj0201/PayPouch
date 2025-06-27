// server.js
// This version includes critical security enhancements:
// 1. API Rate Limiting to prevent abuse.
// 2. Server-side input validation to ensure data integrity.

// --- Dependencies ---
const express = require('express');
const cors = require('cors');
// ** FIX: Load environment variables at the very top **
require('dotenv').config();
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, QueryCommand, UpdateCommand, DeleteCommand } = require("@aws-sdk/lib-dynamodb");
const { v4: uuidv4 } = require('uuid');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
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


// UNPROTECTED ROUTE: For creating a new user and Stripe Customer.
app.post('/api/create-user',
    body('email').isEmail(),
    body('firstName').isString().notEmpty(),
    body('lastName').isString().notEmpty(),
    body('userId').isString().notEmpty(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { userId, email, firstName, lastName } = req.body;
        try {
            const customer = await stripe.customers.create({
                name: `${firstName} ${lastName}`,
                email: email,
                metadata: { paypouchUserId: userId }
            });
            res.status(201).json({ stripeCustomerId: customer.id });
        } catch (error) {
            console.error("Stripe error creating customer:", error);
            res.status(500).json({ message: 'Failed to create Stripe customer.' });
        }
    }
);

// PROTECTED ROUTE: For saving a payment method to a customer.
app.post('/api/save-payment-method',
    authorizationMiddleware,
    body('stripeCustomerId').isString().notEmpty(),
    body('paymentMethodId').isString().notEmpty(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { stripeCustomerId, paymentMethodId } = req.body;
        try {
            await stripe.paymentMethods.attach(paymentMethodId, {
                customer: stripeCustomerId,
            });
            await stripe.customers.update(stripeCustomerId, {
                invoice_settings: {
                    default_payment_method: paymentMethodId,
                },
            });
            res.status(200).json({ message: 'Payment method saved successfully.' });
        } catch (error) {
            console.error("Stripe error saving payment method:", error);
            res.status(500).json({ message: 'Failed to save payment method.' });
        }
    }
);

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
    body('subscriptionName').isString().isLength({ min: 1, max: 100 }).withMessage('Subscription name must be between 1 and 100 characters.'),
    body('cost').isFloat({ gt: 0 }).withMessage('Cost must be a number greater than 0.'),

    async (req, res) => {
        // ** NEW: Add a debug log to inspect the decoded token **
        console.log('[DEBUG] Decoded JWT User Object:', JSON.stringify(req.user, null, 2));

        // ** NEW: Check for validation errors **
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const userId = req.user.sub; // Get userId securely from the decoded token
        
        // ** NEW: Add a specific check for the userId **
        if (!userId) {
            console.error('[ERROR] User ID (sub) not found in the decoded JWT token.');
            return res.status(500).json({ message: 'Internal Server Error: User ID missing from token.' });
        }

        const { subscriptionName, cost } = req.body;
        
        console.log(`User '${userId}' is creating a subscription for '${subscriptionName}'...`);


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


// ** NEW: PROTECTED: PUT /api/subscriptions/:subscriptionId (Update) **
app.put(
    '/api/subscriptions/:subscriptionId',
    authorizationMiddleware,
    param('subscriptionId').isString().notEmpty(),
    body('subscriptionName').isString().notEmpty(),
    body('cost').isFloat({ gt: 0 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const userId = req.user.sub;
        const { subscriptionId } = req.params;
        const { subscriptionName, cost} = req.body;

        const command = new UpdateCommand({
            TableName: TABLE_NAME,
            Key: { userId, subscriptionId },
            ConditionExpression: "attribute_exists(userId)",
            UpdateExpression: "set subscriptionName = :name, cost = :cost",
            ExpressionAttributeValues: {
                ":name": subscriptionName,
                ":cost": parseFloat(cost),
            },
            ReturnValues: "ALL_NEW",
        });

        try {
            const { Attributes } = await docClient.send(command);
            res.status(200).json(Attributes);
        } catch (error) {
            if (error.name === 'ConditionalCheckFailedException') {
                return res.status(404).json({ message: 'Subscription not found or you do not have permission to edit it.' });
            }
            console.error("DynamoDB Update Error:", error);
            res.status(500).json({ message: 'Failed to update subscription' });
        }
    }
);

// ** NEW: PROTECTED: DELETE /api/subscriptions/:subscriptionId (Delete) **
app.delete(
    '/api/subscriptions/:subscriptionId',
    authorizationMiddleware,
    param('subscriptionId').isString().notEmpty(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const userId = req.user.sub;
        const { subscriptionId } = req.params;

        const command = new DeleteCommand({
            TableName: TABLE_NAME,
            Key: { userId, subscriptionId },
            ConditionExpression: "attribute_exists(userId)",
        });

        try {
            await docClient.send(command);
            res.status(200).json({ message: 'Subscription deleted successfully' });
        } catch (error) {
            if (error.name === 'ConditionalCheckFailedException') {
                return res.status(404).json({ message: 'Subscription not found or you do not have permission to delete it.' });
            }
            console.error("DynamoDB Delete Error:", error);
            res.status(500).json({ message: 'Failed to delete subscription' });
        }
    }
);


// --- Server Activation ---
app.listen(PORT, () => {
    console.log(`PayPouch server is running on http://localhost:${PORT}`);
});
