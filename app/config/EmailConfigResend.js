
// require('dotenv').config();
// const { Resend } = require("resend");
// const resend = new Resend(process.env.RESEND_API_KEY);

// async function sendEmail({ to, subject, html }) {
//     try {
//         const emailSend = await resend.emails.send({
//         from: "sdlc.schoollms@gmail.com",
//         to,
//         subject,
//         html
//     });

//     console.log("Resend API Response:", emailSend);
//     return emailSend;
//     } catch (error) {
//         console.error("Resend Error:", error);
//         throw new Error(error.message);
//     }
// }

// module.exports = { sendEmail };