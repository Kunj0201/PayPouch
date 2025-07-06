// server.js
// This version includes critical security enhancements:
// 1. API Rate Limiting to prevent abuse.
// 2. Server-side input validation to ensure data integrity.

// --- Dependencies ---
const express = require('express');
const cors = require('cors');

const path = require('path');
const nodemailer = require('nodemailer'); // Import Nodemailer

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
const PORT = process.env.PORT || 80;
const TABLE_NAME = 'paypouch-subscriptions';

// --- AWS SDK Configuration ---
const dynamoDBClient = new DynamoDBClient({ region: "us-east-1" });
const docClient = DynamoDBDocumentClient.from(dynamoDBClient);

// --- Middleware ---

// ** FIX: Create a robust CORS options object **
const corsOptions = {
  // The origin of your frontend application. Must be an exact match.
  origin: 'https://paypouch.org', 

  // The HTTP methods you are using in your application.
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE", 

  // Headers your frontend is sending. 'Authorization' is critical.
  allowedHeaders: "Content-Type,Authorization" 
};

// Enable CORS with your specific options.
app.use(cors(corsOptions));

// The rest of your middleware
app.use(express.json());

// ADD THIS HEALTH CHECK ENDPOINT
app.get('/health', (req, res) => {
  res.status(200).json({ status: "ok", message: "PayPouch server is running." });
});

// ** NEW: Rate Limiting Middleware **
// This will limit each IP address to 100 requests per 15 minutes.
const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
        standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
        legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use(limiter); // Apply the rate limiting middleware to all requests

// --- Nodemailer Transporter Setup ---
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

transporter.verify(function(error, success) {
    if (error) {
        console.log('Error with email transporter configuration:', error);
    } else {
        console.log('Email transporter is configured and ready to send emails.');
    }
});

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

// PROTECTED ROUTE: For retrieving a customer's payment method from Stripe.
app.get('/api/get-payment-method',
    authorizationMiddleware,
    async (req, res) => {
        const { stripeCustomerId } = req.query;
        if (!stripeCustomerId) {
            return res.status(400).json({ message: 'Stripe customer ID is required.' });
        }

        try {
            const customer = await stripe.customers.retrieve(stripeCustomerId, {
                expand: ['invoice_settings.default_payment_method']
            });

            if (customer.invoice_settings.default_payment_method) {
                res.status(200).json({ paymentMethod: customer.invoice_settings.default_payment_method });
            } else {
                res.status(404).json({ message: 'No default payment method found.' });
            }
        } catch (error) {
            console.error("Stripe error retrieving payment method:", error);
            res.status(500).json({ message: 'Failed to retrieve payment method from Stripe.' });
        }
    }
);

app.get(
    '/api/user-profile',
    authorizationMiddleware, // Ensures the user is logged in
    async (req, res) => {
        const userId = req.user.sub; // Get userId securely from the decoded token

        if (!userId) {
            return res.status(400).json({ message: 'User ID not found in token.' });
        }

        try {
            // In a complete application, you would fetch this from a user profile table
            // in DynamoDB that links your Cognito User ID to the Stripe Customer ID.
            // For now, we will retrieve it directly from Stripe's API.
            const customers = await stripe.customers.list({
                email: req.user.email,
                limit: 1
            });

            if (customers.data.length === 0) {
                return res.status(404).json({ message: 'Stripe customer not found.' });
            }

            const customer = customers.data[0];
            res.status(200).json({
                userId: userId,
                stripeCustomerId: customer.id
                // Add any other user details you might store
            });

        } catch (error) {
            console.error("Error fetching user profile:", error);
            res.status(500).json({ message: 'Failed to retrieve user profile.' });
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
    body('renewalDate').optional().isISO8601().withMessage('Invalid date format for renewalDate. Use ISO 8601.'),

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

        const { subscriptionName, cost, renewalDate } = req.body;
        
        console.log(`User '${userId}' is creating a subscription for '${subscriptionName}'...`);


        const subscriptionId = uuidv4();
        const newSubscription = {
            userId: userId,
            subscriptionId: subscriptionId,
            subscriptionName: subscriptionName,
            cost: parseFloat(cost), // Ensure cost is a number
	    renewalDate: renewalDate,
            createdAt: new Date().toISOString(),
        };
	
	console.log(`User '${userId}' is creating a subscription for date '${renewalDate}'...`);
        
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
    body('renewalDate').optional().isISO8601().withMessage('Invalid date format for renewalDate. Use ISO 8601.'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const userId = req.user.sub;
        const { subscriptionId } = req.params;
        const { subscriptionName, cost, renewalDate} = req.body;

        const command = new UpdateCommand({
            TableName: TABLE_NAME,
            Key: { userId, subscriptionId },
            ConditionExpression: "attribute_exists(userId)",
            UpdateExpression: "set subscriptionName = :name, cost = :cost, renewalDate = :renewalDate",
            ExpressionAttributeValues: {
                ":name": subscriptionName,
                ":cost": parseFloat(cost),
		":renewalDate": renewalDate,
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

// --- UNPROTECTED ROUTE: For submitting feedback ---
app.post('/api/feedback',
    body('email').isEmail().withMessage('A valid email is required.'),
    body('message').isString().notEmpty().withMessage('Message cannot be empty.'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, message } = req.body;

        const mailOptions = {
            from: `"PayPouch Feedback" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER, // Sends the email to yourself
            subject: 'New Feedback from PayPouch User',
            html: `
                <p>You have received new feedback.</p>
                <h3>Contact Details</h3>
                <ul>
                    <li><strong>Email:</strong> ${email}</li>
                </ul>
                <h3>Message</h3>
                <p>${message}</p>
            `
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log('Feedback email sent successfully.');
            res.status(200).json({ message: 'Feedback received and email sent.' });
        } catch (error) {
            console.error('Failed to send feedback email:', error);
            res.status(500).json({ message: 'There was an error sending the feedback email.' });
        }
    }
);


// --- Server Activation ---
app.listen(PORT, () => {
    console.log(`PayPouch server is running on http://localhost:${PORT}`);
});
