// src/components/OTPForm.jsx
import React, { useState, useEffect } from "react";

const OTPForm = ({ onVerify }) => {
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [timer, setTimer] = useState(30); // Timer for resend OTP
  const [isResendAllowed, setIsResendAllowed] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false); // Add a flag to prevent multiple submissions

  const handleOtpChange = (e, index) => {
    const value = e.target.value;
    if (/[0-9]/.test(value) || value === "") {
      const newOtp = [...otp];
      newOtp[index] = value;
      setOtp(newOtp);
      if (value !== "" && index < otp.length - 1) {
        document.getElementById(`otp-input-${index + 1}`).focus();
      }
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isSubmitting) return; // Prevent multiple submissions
    setIsSubmitting(true);
    const otpString = otp.join("");
    console.log("OTP Submitted:", otpString);

    if (onVerify(otpString)) {
      console.log("OTP verified successfully");
    } else {
      alert("Invalid OTP. Please try again.");
    }
    setIsSubmitting(false);
  };

  useEffect(() => {
    if (timer === 0) {
      setIsResendAllowed(true);
    } else {
      const interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [timer]);

  const handleResendOtp = () => {
    if (isResendAllowed) {
      setTimer(30); // Reset the timer
      setIsResendAllowed(false);
      console.log("OTP resent");
      // Trigger resend OTP request to backend here
    }
  };

  return (
    <div className="max-w-sm mx-auto p-8 bg-white shadow-md rounded-lg">
      <h2 className="text-2xl font-semibold text-center mb-4">Enter OTP</h2>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex space-x-2 justify-center">
          {otp.map((digit, index) => (
            <input
              key={index}
              id={`otp-input-${index}`}
              type="text"
              value={digit}
              onChange={(e) => handleOtpChange(e, index)}
              maxLength={1}
              autoFocus={index === 0}
              className="w-12 h-12 text-center text-xl border border-gray-300 rounded-md focus:ring focus:ring-blue-500"
            />
          ))}
        </div>

        <button
          type="submit"
          className="w-full py-2 mt-4 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          disabled={isSubmitting} // Disable the button while submitting
        >
          {isSubmitting ? "Submitting..." : "Submit OTP"}
        </button>
      </form>

      <div className="text-center mt-4">
        {isResendAllowed ? (
          <button
            onClick={handleResendOtp}
            className="text-blue-600 hover:underline"
          >
            Resend OTP
          </button>
        ) : (
          <span>Resend OTP in {timer}s</span>
        )}
      </div>
    </div>
  );
};

export default OTPForm;
