const nodemailer = require("nodemailer");

const sendEmail = async (email, subject, message) => {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    await transporter.sendMail({
        from: process.env.EMAIL,
        to: email,
        subject,
        text: message,
    });
};

module.exports = sendEmail;
