const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { db } = require('../config/firebase');
const {
  validateSIMRegistration,
  handleValidationErrors,
  sanitizeInput,
} = require('../middleware/validation');
const { verifyJWT, requireMFA } = require('../middleware/auth');

/**
 * POST /api/sim/register
 * Register new SIM (requires MFA verification)
 */
router.post(
  '/register',
  verifyJWT,
  requireMFA,
  sanitizeInput,
  validateSIMRegistration,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { mobileNetwork, mobileNumber, deliveryAddress, paymentAddress, sameAsDelivery } = req.body;
      const userId = req.user.id;
      const cnic = req.user.cnic;

      // Check if user has 5 active SIMs (enforced by smart contract)
      // const activeSIMsResult = await fabricClient.evaluateTransaction(
      //   'getActiveSIMCount',
      //   cnic
      // );
      // const activeSIMsData = JSON.parse(activeSIMsResult);
      // if (activeSIMsData.activeSIMCount >= 5) {
      //   return res.status(403).json({
      //     error: 'Maximum 5 SIMs allowed per CNIC',
      //     message: 'Please deactivate an existing SIM to register a new one'
      //   });
      // }

      // Generate transaction and tracking IDs
      const transactionId = uuidv4();
      const trackingNumber = crypto.randomBytes(12).toString('hex').toUpperCase();

      // Prepare SIM registration data
      const simRegistration = {
        transactionId,
        trackingNumber,
        cnic,
        userId,
        mobileNetwork,
        mobileNumber,
        deliveryAddress,
        paymentAddress: sameAsDelivery ? deliveryAddress : paymentAddress,
        status: 'processing',
        registeredAt: new Date().toISOString(),
      };

      // Store SIM in database
      const simRef = await db.collection('sims').add({
        uid: userId,
        cnic,
        mobileNumber,
        networkProvider: mobileNetwork,
        status: 'processing',
        registrationDate: new Date(),
        transactionId,
        trackingNumber,
        deliveryAddress,
        paymentAddress: sameAsDelivery ? deliveryAddress : paymentAddress,
        createdAt: new Date(),
      });

      // Store order in database
      const orderRef = await db.collection('orders').add({
        uid: userId,
        cnic,
        simId: simRef.id,
        transactionId,
        trackingNumber,
        orderDate: new Date(),
        status: 'processing',
        deliveryAddress,
        paymentAddress: sameAsDelivery ? deliveryAddress : paymentAddress,
        timeline: [{
          status: 'Processing',
          timestamp: new Date(),
          description: 'SIM registration request submitted'
        }],
        createdAt: new Date(),
      });

      // Submit to Hyperledger Fabric blockchain
      // const result = await fabricClient.submitTransaction(
      //   'registerSIM',
      //   cnic,
      //   fullName,
      //   fatherName,
      //   dateOfBirth,
      //   mobileNumber,
      //   mobileNetwork
      // );

      // Log to audit trail
      // await logAuditEvent(userId, 'SIM_REGISTERED', 'sim', trackingNumber, req, simRegistration);

      res.status(201).json({
        message: 'SIM registration request submitted successfully',
        transactionId,
        trackingNumber,
        status: 'processing',
        details: {
          mobileNetwork,
          mobileNumber,
          deliveryAddress,
          estimatedDelivery: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(), // 5 days
        },
      });
    } catch (error) {
      console.error('[Error] SIM Registration:', error);
      res.status(500).json({ error: 'SIM registration failed' });
    }
  }
);

/**
 * POST /api/sim/deactivate
 * Deactivate a registered SIM
 */
router.post(
  '/deactivate',
  verifyJWT,
  requireMFA,
  sanitizeInput,
  async (req, res) => {
    try {
      const { simId } = req.body;
      const cnic = req.user.cnic;
      const userId = req.user.id;

      if (!simId) {
        return res.status(400).json({ error: 'SIM ID is required' });
      }

      // Call Hyperledger Fabric chaincode
      // const result = await fabricClient.submitTransaction(
      //   'deactivateSIM',
      //   cnic,
      //   simId
      // );

      // Log deactivation
      // await logAuditEvent(userId, 'SIM_DEACTIVATED', 'sim', simId, req);

      res.json({
        message: 'SIM deactivated successfully',
        simId,
        status: 'inactive',
        deactivatedAt: new Date().toISOString(),
      });
    } catch (error) {
      console.error('[Error] SIM Deactivation:', error);
      res.status(500).json({ error: 'SIM deactivation failed' });
    }
  }
);

/**
 * GET /api/sim/registered
 * Get all SIMs registered by user
 */
router.get('/registered', verifyJWT, async (req, res) => {
  try {
    const cnic = req.user.cnic;

    // Query Hyperledger Fabric
    // const result = await fabricClient.evaluateTransaction(
    //   'getSIMsByCNIC',
    //   cnic
    // );
    // const sims = JSON.parse(result);

    // Mock response
    const sims = [
      {
        simId: 'SIM_1234567890',
        simNumber: '03001234567',
        operator: 'Jazz',
        status: 'active',
        registrationDate: new Date().toISOString(),
      },
    ];

    res.json({
      message: 'SIMs retrieved successfully',
      count: sims.length,
      sims,
    });
  } catch (error) {
    console.error('[Error] Fetching SIMs:', error);
    res.status(500).json({ error: 'Failed to fetch SIMs' });
  }
});

/**
 * GET /api/sim/track/:trackingNumber
 * Track SIM registration status
 */
router.get('/track/:trackingNumber', async (req, res) => {
  try {
    const { trackingNumber } = req.params;

    if (!trackingNumber || trackingNumber.length < 10) {
      return res.status(400).json({ error: 'Invalid tracking number' });
    }

    // Query database for tracking status
    // const result = await db.query(
    //   'SELECT * FROM blockchain_events WHERE transaction_id = $1 OR tracking_number = $1',
    //   [trackingNumber]
    // );
    // if (result.rows.length === 0) {
    //   return res.status(404).json({ error: 'Tracking number not found' });
    // }
    // const order = result.rows[0];

    // Mock response
    const order = {
      trackingNumber,
      transactionId: uuidv4(),
      status: 'in_transit',
      mobileNetwork: 'Jazz',
      mobileNumber: '03001234567',
      timeline: [
        { step: 'Processing', date: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), completed: true },
        { step: 'Shipped', date: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(), completed: true },
        { step: 'In Transit', date: new Date().toISOString(), completed: true },
        { step: 'Delivered', date: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(), completed: false },
      ],
    };

    res.json({
      message: 'Order status retrieved',
      order,
    });
  } catch (error) {
    console.error('[Error] Tracking SIM:', error);
    res.status(500).json({ error: 'Failed to track order' });
  }
});

/**
 * GET /api/sim/active-count
 * Check if user can register more SIMs
 */
router.get('/active-count', verifyJWT, async (req, res) => {
  try {
    const cnic = req.user.cnic;

    // Query Hyperledger Fabric
    // const result = await fabricClient.evaluateTransaction(
    //   'getActiveSIMCount',
    //   cnic
    // );
    // const countData = JSON.parse(result);

    // Mock response
    const countData = {
      cnic,
      activeSIMCount: 3,
      canRegisterMore: true,
      remainingSlots: 2,
    };

    res.json(countData);
  } catch (error) {
    console.error('[Error] Checking SIM Count:', error);
    res.status(500).json({ error: 'Failed to check SIM count' });
  }
});

module.exports = router;
