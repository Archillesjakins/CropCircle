import React, { useState } from "react";

const CustomerSignUp = () => {
  const [formData, setFormData] = useState({
    fullName: "",
    email: "",
    password: "",
    confirmPassword: "",
  });
  const [errors, setErrors] = useState({});
  const [otpSent, setOtpSent] = useState(false);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const validateForm = () => {
    const newErrors = {};
    if (!formData.fullName) newErrors.fullName = "Full Name is required";
    if (!formData.email) {
      newErrors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Invalid email format";
    }
    if (!formData.password) newErrors.password = "Password is required";
    if (formData.password && formData.password.length < 8) {
      newErrors.password = "Password must be at least 8 characters";
    }
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (validateForm()) {
      setOtpSent(true);
      console.log("OTP sent for email verification");
    }
  };

  const closeModal = () => {
    setOtpSent(false);
  };

  return (
    <div className="flex h-screen w-screen">
      {/* Image Section */}
      <div
        className="hidden lg:block w-1/2 h-full bg-cover bg-center"
        style={{
          backgroundImage: "url('/src/assets/signUp.jpg')",
        }}
      ></div>

      {/* Form Section */}
      <div className="flex items-center justify-center w-full  lg:w-1/2 lg:rounded-l-[80px] z-10 shadow-lg">
        <div className="w-full max-w-md p-10">
          <h2 className="text-3xl font-bold text-green-600 text-center mb-4">
            CUSTOMER SIGN UP
          </h2>
          <p className="text-lg font-semibold text-center mb-2">
            Welcome to <span className="font-bold">CropCircle</span>
          </p>
          <p className="text-center text-sm text-gray-600 mb-6">
            Join thousands of users who have already signed up
          </p>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <input
                type="text"
                name="fullName"
                placeholder="Full name"
                value={formData.fullName}
                onChange={handleChange}
                className="mt-1 block w-full p-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 placeholder-gray-500"
              />
              {errors.fullName && (
                <p className="text-red-500 text-xs mt-1">{errors.fullName}</p>
              )}
            </div>

            <div>
              <input
                type="email"
                name="email"
                placeholder="Email"
                value={formData.email}
                onChange={handleChange}
                className="mt-1 block w-full p-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 placeholder-gray-500"
              />
              {errors.email && (
                <p className="text-red-500 text-xs mt-1">{errors.email}</p>
              )}
            </div>

            <div>
              <input
                type="password"
                name="password"
                placeholder="Password"
                value={formData.password}
                onChange={handleChange}
                className="mt-1 block w-full p-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 placeholder-gray-500"
              />
              {errors.password && (
                <p className="text-red-500 text-xs mt-1">{errors.password}</p>
              )}
            </div>

            <div>
              <input
                type="password"
                name="confirmPassword"
                placeholder="Confirm password"
                value={formData.confirmPassword}
                onChange={handleChange}
                className="mt-1 block w-full p-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 placeholder-gray-500"
              />
              {errors.confirmPassword && (
                <p className="text-red-500 text-xs mt-1">
                  {errors.confirmPassword}
                </p>
              )}
            </div>

            <button
              type="submit"
              className="w-full bg-green-600 text-white py-3 rounded-md hover:bg-green-700 transition text-lg font-semibold"
            >
              Sign Up
            </button>
          </form>

          <p className="mt-4 text-center text-gray-600">
            Already have an Account?{" "}
            <a
              href="/customer/login"
              className="text-green-600 hover:underline"
            >
              Log In
            </a>
          </p>

          {/* OTP Sent Modal */}
          {otpSent && (
            <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white p-6 rounded shadow-lg text-center">
                <h5 className="text-green-700 font-bold text-lg mb-4">
                  OTP Sent
                </h5>
                <p className="text-green-500">
                  Please check your email to verify your account.
                </p>
                <button
                  onClick={closeModal}
                  className="mt-4 bg-green-600 text-white py-2 px-4 rounded hover:bg-green-700"
                >
                  Close
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CustomerSignUp;
