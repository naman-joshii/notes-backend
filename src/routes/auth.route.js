import express from 'express';
import { 
    signup, 
    verifyOtpAndCreateUser, 
    requestLoginOtp,         // Replaces 'login'
    verifyLoginOtp,    
    checkAuth,
    logout
} from '../controllers/auth.controller.js';


const router = express.Router();

// --- User Signup ---
router.post('/signup', signup);
// Renamed for clarity to distinguish from login OTP verification
router.post('/verify-signup', verifyOtpAndCreateUser); 

// --- User Login (Two-Step OTP) ---
// Step 1: User provides email to request an OTP
router.post('/login', requestLoginOtp); 
// Step 2: User provides email and OTP to get a token

router.post('/verify-login', verifyLoginOtp);
router.get('/check', checkAuth);
router.post("/logout", logout);

export default router;
