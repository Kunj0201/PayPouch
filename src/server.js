// server.js
// This file sets up a local web server with a connection to a local DynamoDB instance.
// It creates the API endpoints needed for the PayPouch application to have persistent data.


// --- Dependencies ---
const express = require('express');
const cors = require('cors');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, QueryCommand } = require("@aws-sdk/lib-dynamodb");
const { v4: uuidv4 } = require('uuid');

// --- Initialization ---
const app = express();
const PORT = 3000;
const TABLE_NAME = 'paypouch-subscriptions';

// --- AWS SDK Configuration for Local DynamoDB ---
// This configuration tells the AWS SDK to connect to our local database instance
// instead of the actual AWS cloud service.
const dynamoDBClient = new DynamoDBClient({
    region: 'localhost', // Dummy region for local development
    endpoint: 'http://localhost:8000', // The default endpoint for DynamoDB Local
    credentials: {
        accessKeyId: 'dummyAccessKeyId', // Dummy credentials
        secretAccessKey: 'dummySecretAccessKey',
    },
});
const docClient = DynamoDBDocumentClient.from(dynamoDBClient);


// --- Middleware ---
app.use(express.json());
app.use(cors());


// --- API Routes ---

/**
 * Route:   POST /api/subscriptions
 * Purpose: Creates a new subscription and saves it to the local DynamoDB.
 * Body:    Expects a JSON object with { userId, subscriptionName, cost }
 */
app.post('/api/subscriptions', async (req, res) => {
    console.log('Received request to create a subscription...');
    const { userId, subscriptionName, cost } = req.body;

    if (!userId || !subscriptionName || !cost) {
        return res.status(400).json({ message: 'Missing required fields.' });
    }

    const subscriptionId = uuidv4();
    const newSubscription = {
        userId: userId,
        subscriptionId: subscriptionId,
        subscriptionName: subscriptionName,
        cost: cost,
        createdAt: new Date().toISOString()
    };
    
    // Create the command to put the new item into the DynamoDB table
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
});


/**
 * Route:   GET /api/subscriptions/:userId
 * Purpose: Retrieves all subscriptions for a given user from the local DynamoDB.
 * Params:  Expects a userId in the URL path.
 */
app.get('/api/subscriptions/:userId', async (req, res) => {
    const { userId } = req.params;
    console.log(`Received request to get subscriptions for user: ${userId}`);

    // Create the command to query all items for a specific userId
    const command = new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: "userId = :uid",
        ExpressionAttributeValues: {
            ":uid": userId,
        },
    });

    try {
        const { Items } = await docClient.send(command);
        console.log(`Found ${Items.length} subscriptions for user.`);
        res.status(200).json(Items);
    } catch (error) {
        console.error("DynamoDB error:", error);
        res.status(500).json({ message: 'Failed to retrieve subscriptions.', error: error.message });
    }
});


// --- Server Activation ---
app.listen(PORT, () => {
    console.log(`PayPouch local server is running on http://localhost:${PORT}`);
});
