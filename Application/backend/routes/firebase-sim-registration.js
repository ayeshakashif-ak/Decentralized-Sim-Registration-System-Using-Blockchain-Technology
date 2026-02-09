const express = require('express');
const router = express.Router();
const { db } = require('../config/firebase');
const { verifyJWT } = require('../middleware/auth');
const { validateSIMRegistration } = require('../middleware/validation');
const { auditLog } = require('../utils/audit-logger');
const { submitToBlockchain } = require('../config/fabric-gateway');

// REGISTER SIM endpoint
router.post('/register', verifyJWT, validateSIMRegistration, async (req, res) => {
  try {
    const { uid } = req.user;
    const { 
      networkProvider, 
      mobileNumber, 
      paymentMethod,
      deliveryAddress,
      paymentAddress,
      sameAddressForPayment
    } = req.body;

    // Get user data
    const userDoc = await db.collection('users').doc(uid).get();
    const user = userDoc.data();

    // Check if user has 5 active SIMs
    const activeSims = user.registeredSims?.filter(sim => sim.status === 'active') || [];
    if (activeSims.length >= 5) {
      return res.status(403).json({ 
        error: 'Maximum SIM limit reached. Deactivate a SIM to register a new one.' 
      });
    }

    // Validate mobile number format
    if (!/^03\d{9}$/.test(mobileNumber)) {
      return res.status(400).json({ error: 'Invalid mobile number format' });
    }

    // Check if mobile number is already registered
    const existingSimSnapshot = await db.collection('sims')
      .where('mobileNumber', '==', mobileNumber)
      .where('status', '==', 'active')
      .limit(1)
      .get();

    if (!existingSimSnapshot.empty) {
      return res.status(400).json({ error: 'Mobile number already registered' });
    }

    // Generate transaction ID and tracking number
    const transactionId = `TXN-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
    const trackingNumber = `TRK-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    // Create SIM record in Firestore
    const simData = {
      uid,
      cnic: user.cnic,
      transactionId,
      trackingNumber,
      networkProvider,
      mobileNumber,
      paymentMethod,
      deliveryAddress,
      paymentAddress: sameAddressForPayment ? deliveryAddress : paymentAddress,
      status: 'processing',
      registrationDate: new Date(),
      activationDate: null,
      deactivationDate: null,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const simDocRef = await db.collection('sims').add(simData);

    // Create order record
    const orderData = {
      uid,
      transactionId,
      trackingNumber,
      simId: simDocRef.id,
      status: 'confirmed',
      orderDate: new Date(),
      estimatedDelivery: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      timeline: [
        { status: 'confirmed', timestamp: new Date(), description: 'Order confirmed' },
        { status: 'processing', timestamp: new Date(Date.now() + 2 * 60 * 60 * 1000), description: 'Processing' },
        { status: 'shipped', timestamp: new Date(Date.now() + 12 * 60 * 60 * 1000), description: 'Shipped' },
        { status: 'in-transit', timestamp: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), description: 'In Transit' },
        { status: 'delivered', timestamp: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), description: 'Delivered' }
      ],
      createdAt: new Date()
    };

    await db.collection('orders').add(orderData);

    // Update user's SIM list
    const updatedSims = [...(user.registeredSims || []), {
      simId: simDocRef.id,
      mobileNumber,
      networkProvider,
      transactionId,
      trackingNumber,
      status: 'active',
      registrationDate: new Date().toISOString()
    }];

    await db.collection('users').doc(uid).update({
      registeredSims: updatedSims,
      updatedAt: new Date()
    });

    // Log to blockchain (Hyperledger Fabric)
    try {
      await submitToBlockchain({
        action: 'registerSim',
        cnic: user.cnic,
        mobileNumber,
        networkProvider,
        transactionId,
        timestamp: new Date().toISOString()
      });
    } catch (fabricError) {
      console.error('Fabric logging error:', fabricError);
      // Continue even if blockchain logging fails - this is a secondary concern
    }

    // Audit log
    await auditLog({
      userId: uid,
      action: 'SIM_REGISTRATION',
      details: {
        transactionId,
        trackingNumber,
        mobileNumber,
        networkProvider,
        timestamp: new Date().toISOString()
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.status(201).json({
      success: true,
      message: 'SIM registered successfully',
      transaction: {
        transactionId,
        trackingNumber,
        mobileNumber,
        networkProvider,
        status: 'processing',
        registrationDate: new Date()
      }
    });

  } catch (error) {
    console.error('SIM registration error:', error);
    res.status(500).json({ error: 'Failed to register SIM' });
  }
});

// GET REGISTERED SIMS endpoint
router.get('/my-sims', verifyJWT, async (req, res) => {
  try {
    const { uid } = req.user;

    const userDoc = await db.collection('users').doc(uid).get();
    const user = userDoc.data();

    const simsData = user.registeredSims || [];

    res.json({
      success: true,
      sims: simsData,
      summary: {
        total: simsData.length,
        active: simsData.filter(sim => sim.status === 'active').length,
        inactive: simsData.filter(sim => sim.status === 'inactive').length,
        pending: simsData.filter(sim => sim.status === 'processing').length
      }
    });

  } catch (error) {
    console.error('Get SIMs error:', error);
    res.status(500).json({ error: 'Failed to fetch SIMs' });
  }
});

// DEACTIVATE SIM endpoint
router.post('/deactivate/:transactionId', verifyJWT, async (req, res) => {
  try {
    const { uid } = req.user;
    const { transactionId } = req.params;

    const userDoc = await db.collection('users').doc(uid).get();
    const user = userDoc.data();

    // Find the SIM to deactivate
    const simToDeactivate = user.registeredSims?.find(sim => sim.transactionId === transactionId);
    if (!simToDeactivate) {
      return res.status(404).json({ error: 'SIM not found' });
    }

    // Update user's SIM list
    const updatedSims = user.registeredSims.map(sim => {
      if (sim.transactionId === transactionId) {
        return { ...sim, status: 'inactive', deactivationDate: new Date().toISOString() };
      }
      return sim;
    });

    await db.collection('users').doc(uid).update({
      registeredSims: updatedSims,
      updatedAt: new Date()
    });

    // Update SIM document status
    const simSnapshot = await db.collection('sims')
      .where('transactionId', '==', transactionId)
      .limit(1)
      .get();

    if (!simSnapshot.empty) {
      await db.collection('sims').doc(simSnapshot.docs[0].id).update({
        status: 'inactive',
        deactivationDate: new Date(),
        updatedAt: new Date()
      });

      // Log to blockchain
      try {
        await submitToBlockchain({
          action: 'deactivateSim',
          cnic: user.cnic,
          mobileNumber: simToDeactivate.mobileNumber,
          transactionId,
          timestamp: new Date().toISOString()
        });
      } catch (fabricError) {
        console.error('Fabric logging error:', fabricError);
      }
    }

    // Audit log
    await auditLog({
      userId: uid,
      action: 'SIM_DEACTIVATION',
      details: {
        transactionId,
        mobileNumber: simToDeactivate.mobileNumber,
        timestamp: new Date().toISOString()
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      message: 'SIM deactivated successfully',
      updatedSims
    });

  } catch (error) {
    console.error('Deactivate SIM error:', error);
    res.status(500).json({ error: 'Failed to deactivate SIM' });
  }
});

// TRACK ORDER endpoint
router.get('/track/:trackingNumber', async (req, res) => {
  try {
    const { trackingNumber } = req.params;

    const orderSnapshot = await db.collection('orders')
      .where('trackingNumber', '==', trackingNumber)
      .limit(1)
      .get();

    if (orderSnapshot.empty) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orderSnapshot.docs[0].data();

    res.json({
      success: true,
      order: {
        trackingNumber: order.trackingNumber,
        transactionId: order.transactionId,
        status: order.status,
        orderDate: order.orderDate,
        estimatedDelivery: order.estimatedDelivery,
        timeline: order.timeline
      }
    });

  } catch (error) {
    console.error('Track order error:', error);
    res.status(500).json({ error: 'Failed to track order' });
  }
});

module.exports = router;
