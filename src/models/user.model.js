import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  dob: { type: Date, required: true },
  googleId: { type: String },
  otp: { type: String },
  otpExpires: { type: Date },
});

const User = mongoose.model('User', userSchema);
export default User;