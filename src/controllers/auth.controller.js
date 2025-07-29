import otpGenerator from 'otp-generator';
import { OAuth2Client } from 'google-auth-library';
import jwt from 'jsonwebtoken'; // MODIFIED: Added missing import for JWT
import User from '../models/user.model.js';
import sendEmail from '../lib/sendMail.js';
import dotenv from 'dotenv';

dotenv.config();

// This is fine for sign-up, as the user doesn't exist in the DB yet.
const signupOtpStore = {};

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Helper function to generate a JWT token
const generateToken = (id) => {
    return jwt.sign({ id: id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};


// --- SIGN-UP FLOW ---

export const signup = async (req, res) => {
  try {
    console.log('signup payload:', req.body); // Debug log
    
    const { fullName, email, dob } = req.body;

    if (!fullName || !email || !dob) {
      return res.status(400).json({ message: 'Please enter all fields' });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const otp = otpGenerator.generate(6, { numericOnly: true });
    signupOtpStore[email] = otp; // Store OTP for signup verification
    
    console.log(`Generated OTP for ${email}: ${otp}`);
    console.log('Current signupOtpStore:', signupOtpStore);
    
    // In a real application, you would email this OTP to the user
    try {
      await sendEmail({
          to: email,
          subject: 'Your OTP for Sign Up',
          html: `<p>Your One-Time Password is: <strong>${otp}</strong></p><p>This OTP is valid for 10 minutes.</p>`
      });
      
      const tempUser = { fullName, email, dob };
      res.status(200).json({ 
        message: 'OTP sent successfully. Please verify to complete signup.', 
        tempUser,
        debugOtp: process.env.NODE_ENV === 'development' ? otp : undefined // Only show OTP in development
      });

    } catch (error) {
        console.error('Email sending failed:', error.message);
        res.status(500).json({ 
            message: 'Error sending OTP email.',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Email service unavailable'
        });
    }
  } catch (error) {
    console.error('Error in signup:', error);
    res.status(500).json({ 
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
  }
};

export const verifyOtpAndCreateUser = async (req, res) => {
  try {
    console.log('verify-signup payload:', req.body); // Debug log
    
    const { email, otp, tempUser } = req.body;

    // Validate required fields
    if (!email || !otp || !tempUser) {
      return res.status(400).json({ 
        message: 'Missing required fields: email, otp, and tempUser are required' 
      });
    }

    // Check if OTP exists and matches
    if (!signupOtpStore[email]) {
      return res.status(400).json({ 
        message: 'OTP not found. Please request a new OTP' 
      });
    }

    if (signupOtpStore[email] !== otp) {
      return res.status(400).json({ 
        message: 'Invalid OTP. Please check and try again' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        message: 'User already exists with this email' 
      });
    }

    // Create user
    const user = await User.create({
      fullName: tempUser.fullName,
      email: tempUser.email,
      dob: tempUser.dob,
    });

    // Clean up OTP
    delete signupOtpStore[email];

    if (user) {
      const token = generateToken(user._id.toString());
      console.log("Generated token:", token);
      
      // Set cookie with more permissive settings for development
      res.cookie('jwt', token, {
        httpOnly: true,
        secure: false, // Set to false for development (localhost)
        sameSite: 'lax', // More permissive for development
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });
      
      console.log("Cookie set successfully");
      
      // Send response
      res.status(201).json({
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        token: token,
        message: 'User created successfully'
      });
      
    } else {
      res.status(400).json({ message: 'Failed to create user' });
    }
  } catch (error) {
    console.error('Error in verifyOtpAndCreateUser:', error);
    res.status(500).json({ 
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
  }
};


// --- SIGN-IN (LOGIN) FLOW ---

// NEW: Step 1 - User requests an OTP to log in
export const requestLoginOtp = async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ message: 'User not found. Please sign up first.' });
    }

    const otp = otpGenerator.generate(6, { numericOnly: true });
    user.otp = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minute expiry
    await user.save();
    
    try {
        await sendEmail({
            to: email,
            subject: 'Your OTP for Sign In',
            html: `<p>Your One-Time Password is: <strong>${otp}</strong></p><p>This OTP is valid for 10 minutes.</p>`
        });
        
        res.status(200).json({ message: 'OTP sent to your email.' });

    } catch (error) {
        console.error('Email sending failed:', error.message);
        res.status(500).json({ 
            message: 'Error sending OTP email.',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Email service unavailable'
        });
    }
};

// NEW: Step 2 - User provides the OTP to get a token
export const verifyLoginOtp = async (req, res) => {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ message: 'User not found.' });
    }

    if (user.otp !== otp || user.otpExpires < Date.now()) {
        return res.status(400).json({ message: 'Invalid OTP or OTP has expired.' });
    }

    // Clear the OTP after successful login
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();
    const token = generateToken(user._id.toString());

    res.cookie('jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });
      console.log("Token in cookie:", req.cookies.jwt);
      
      // ✅ Then send response
      res.status(200).json({
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        token: token,
      });
};




export const checkAuth = async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId || decoded.id;

    const user = await User.findById(userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      isAuthenticated: true
    });

  } catch (error) {
    console.error('Error checking auth:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const logout = async(req, res) => {
  try{
      res.cookie("jwt", "", {maxAge: 0});
      res.status(200).json({message: "Logged out successfully"});
  }catch(error){
      console.log(" error in logout", error);
      res.status(500).json({message: "Internal server error"});
  }
}