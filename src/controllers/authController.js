const User = require("../models/User");
const generateOTP = require("../utils/generateOTP");
const sendEmail = require("../utils/sendEmail");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

exports.signup = async (req, res) => {
    const { email } = req.body;
    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            // If an OTP exists for the user, update it, else return email exists message
            if (existingUser.otp && existingUser.otpExpires > Date.now()) {
                // OTP exists and is still valid, update OTP expiration time
                const otp = generateOTP();
                const otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes expiration time
                existingUser.otp = otp;
                existingUser.otpExpires = otpExpires;
                await existingUser.save();

                // Send OTP email
                await sendEmail(email, "Your OTP", `Your OTP is ${otp}`);
                return res.status(200).json({ message: "OTP has been resent to your email" });
            }

            // If OTP doesn't exist or expired, return message
            return res.status(400).json({ message: "Email already exists, but OTP is either expired or not generated" });
        }

        // If no existing user, generate new OTP and create a new user record
        const otp = generateOTP();
        const otpExpires = Date.now() + 10 * 60 * 1000; // OTP expires in 10 minutes

        // Create the new user with OTP
        const newUser = await User.create({ email, otp, otpExpires });

        // Send OTP email
        await sendEmail(email, "Your OTP", `Your OTP is ${otp}`);
        res.status(200).json({ message: "OTP sent to your email" });

    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
};


exports.verifyOTP = async (req, res) => {
    const { email, otp, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "Invalid email" });

        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.otp = undefined;
        user.otpExpires = undefined;

        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.status(200).json({ message: "Signup successful", token });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;
    try {
        // Check if user exists
        const user = await User.findOne({ email });
        
        if (!user) {
            // If the user is not found, return a specific message for "email not found"
            return res.status(404).json({ message: "Email not found" });
        }

        // Check if the password matches
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            // If password doesn't match, return "Invalid credentials"
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // If user and password are correct, generate JWT
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        
        // Send the response with the token
        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        // Catch any errors during the process and send a server error response
        res.status(500).json({ message: "Server error" });
    }
};

