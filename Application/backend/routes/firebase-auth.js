const express = require('express');
const router = express.Router();
const { db, auth } = require('../config/firebase');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { validateSignup, validateLogin } = require('../middleware/validation');
const { auditLog } = require('../utils/audit-logger');
const { verifyJWT } = require('../middleware/auth');

// Helper function to generate JWT tokens
const generateTokens = (uid) => {
  const accessToken = jwt.sign(
    { uid, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRY || '10m' } // Changed from 15m to 10m
  );

  const refreshToken = jwt.sign(
    { uid, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY || '7d' }
  );

  return { accessToken, refreshToken };
};

// SIGNUP endpoint
router.post('/signup', validateSignup, async (req, res) => {
  try {
    const { email, password, name, fatherName, cnic, cnicIssueDate } = req.body;

    // Check if user already exists in Firestore
    const userDoc = await db.collection('users').doc(cnic).get();
    if (userDoc.exists) {
      return res.status(400).json({ error: 'User with this CNIC already exists' });
    }

    // Validate CNIC format (Pakistani CNIC: XXXXX-XXXXXXX-X or 13 digits)
    const cnicRegex = /^(\d{5}-\d{7}-\d{1}|\d{13})$/;
    if (!cnicRegex.test(cnic)) {
      return res.status(400).json({ error: 'Invalid CNIC format. Use XXXXX-XXXXXXX-X or 13 digits' });
    }

    // Create Firebase Auth user
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: name,
      emailVerified: false
    });

    // Hash password for additional security layer
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate MFA secret for future setup
    const mfaSecret = speakeasy.generateSecret({
      name: `DIMS-SR (${email})`,
      issuer: 'DIMS-SR',
      length: 32
    });

    // Store user data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      email,
      name,
      fatherName,
      cnic,
      cnicIssueDate,
      passwordHash: hashedPassword,
      mfaEnabled: false,
      mfaSecret: mfaSecret.base32,
      mfaVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      accountStatus: 'active',
      loginAttempts: 0,
      lastLoginAttempt: null,
      registeredSims: [],
      deactivatedSims: []
    });

    // Log this event to blockchain via Fabric
    await auditLog({
      userId: userRecord.uid,
      action: 'USER_SIGNUP',
      details: {
        email,
        cnic,
        timestamp: new Date().toISOString()
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(userRecord.uid);

    // Store refresh token in Firestore
    await db.collection('sessions').add({
      uid: userRecord.uid,
      refreshToken,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      accessToken,
      refreshToken,
      user: {
        uid: userRecord.uid,
        email,
        name,
        mfaRequired: true
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      error: 'Failed to create account',
      message: error.message 
    });
  }
});

// LOGIN endpoint
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { cnic, password } = req.body;

    // Get user from Firestore by CNIC
    const userSnapshot = await db.collection('users').where('cnic', '==', cnic).limit(1).get();
    
    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'Invalid CNIC or password' });
    }

    const userDoc = userSnapshot.docs[0];
    const user = userDoc.data();

    // Check account status
    if (user.accountStatus !== 'active') {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Check login attempts
    const now = new Date();
    if (user.lastLoginAttempt) {
      const timeDiff = (now - user.lastLoginAttempt.toDate()) / (1000 * 60);
      if (user.loginAttempts >= 5 && timeDiff < 15) {
        return res.status(429).json({ 
          error: 'Too many login attempts. Try again after 15 minutes' 
        });
      }
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      // Increment login attempts
      await db.collection('users').doc(userDoc.id).update({
        loginAttempts: user.loginAttempts + 1,
        lastLoginAttempt: new Date()
      });

      return res.status(401).json({ error: 'Invalid CNIC or password' });
    }

    // Reset login attempts on successful login
    await db.collection('users').doc(userDoc.id).update({
      loginAttempts: 0,
      lastLoginAttempt: null
    });

    // If MFA is enabled, return success with mfaRequired flag
    if (user.mfaEnabled && user.mfaVerified) {
      return res.status(200).json({
        success: true,
        mfaRequired: true,
        tempToken: jwt.sign(
          { uid: userDoc.id, temp: true },
          process.env.JWT_SECRET,
          { expiresIn: '10m' }
        ),
        user: {
          uid: userDoc.id,
          email: user.email,
          name: user.name
        }
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(userDoc.id);

    // Store session
    await db.collection('sessions').add({
      uid: userDoc.id,
      refreshToken,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Log login
    await auditLog({
      userId: userDoc.id,
      action: 'USER_LOGIN',
      details: { email: user.email, timestamp: new Date().toISOString() },
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        uid: userDoc.id,
        email: user.email,
        name: user.name
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// SETUP MFA endpoint
router.post('/mfa/setup', verifyJWT, async (req, res) => {
  try {
    const { uid } = req.user;
    const userDoc = await db.collection('users').doc(uid).get();
    const user = userDoc.data();

    // Generate QR code
    const otpauthUrl = speakeasy.otpauthURL({
      secret: user.mfaSecret,
      encoding: 'base32',
      label: `DIMS-SR (${user.email})`,
      issuer: 'DIMS-SR'
    });

    const qrCode = await QRCode.toDataURL(otpauthUrl);

    res.json({
      success: true,
      qrCode,
      manualEntry: user.mfaSecret,
      message: 'Scan QR code with your authenticator app'
    });

  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({ error: 'MFA setup failed' });
  }
});

// VERIFY MFA CODE endpoint
router.post('/mfa/verify', verifyJWT, async (req, res) => {
  try {
    const { uid } = req.user;
    const { code } = req.body;

    if (!code || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }

    const userDoc = await db.collection('users').doc(uid).get();
    const user = userDoc.data();

    // Verify TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }

    // Mark MFA as verified and enabled
    await db.collection('users').doc(uid).update({
      mfaEnabled: true,
      mfaVerified: true,
      updatedAt: new Date()
    });

    // Log MFA setup
    await auditLog({
      userId: uid,
      action: 'MFA_SETUP_COMPLETE',
      details: { timestamp: new Date().toISOString() },
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      message: 'MFA enabled successfully'
    });

  } catch (error) {
    console.error('MFA verification error:', error);
    res.status(500).json({ error: 'MFA verification failed' });
  }
});

// VERIFY MFA CODE ON LOGIN endpoint
router.post('/mfa/verify-login', async (req, res) => {
  try {
    const { tempToken, code } = req.body;

    if (!code || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }

    // Verify temp token
    let decoded;
    try {
      decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
      if (!decoded.temp) throw new Error('Not a temp token');
    } catch (error) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const userDoc = await db.collection('users').doc(decoded.uid).get();
    const user = userDoc.data();

    // Verify TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }

    // Generate full tokens
    const { accessToken, refreshToken } = generateTokens(decoded.uid);

    // Store session
    await db.collection('sessions').add({
      uid: decoded.uid,
      refreshToken,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Log successful MFA login
    await auditLog({
      userId: decoded.uid,
      action: 'MFA_LOGIN_SUCCESS',
      details: { email: user.email, timestamp: new Date().toISOString() },
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        uid: decoded.uid,
        email: user.email,
        name: user.name
      }
    });

  } catch (error) {
    console.error('MFA login error:', error);
    res.status(500).json({ error: 'MFA verification failed' });
  }
});

// REFRESH TOKEN endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Check if session exists in Firestore
    const sessionSnapshot = await db.collection('sessions')
      .where('uid', '==', decoded.uid)
      .where('refreshToken', '==', refreshToken)
      .limit(1)
      .get();

    if (sessionSnapshot.empty) {
      return res.status(401).json({ error: 'Session not found' });
    }

    // Generate new access token
    const accessToken = jwt.sign(
      { uid: decoded.uid, type: 'access' },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY || '10m' } // Changed from 15m to 10m
    );

    res.json({ success: true, accessToken });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// LOGOUT endpoint
router.post('/logout', verifyJWT, async (req, res) => {
  try {
    const { uid } = req.user;
    const { refreshToken } = req.body;

    if (refreshToken) {
      // Delete session from Firestore
      const sessionSnapshot = await db.collection('sessions')
        .where('uid', '==', uid)
        .where('refreshToken', '==', refreshToken)
        .limit(1)
        .get();

      if (!sessionSnapshot.empty) {
        await db.collection('sessions').doc(sessionSnapshot.docs[0].id).delete();
      }
    }

    // Log logout
    await auditLog({
      userId: uid,
      action: 'USER_LOGOUT',
      details: { timestamp: new Date().toISOString() },
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({ success: true, message: 'Logged out successfully' });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

module.exports = router;
