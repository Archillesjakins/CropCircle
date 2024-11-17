import React, { useState } from "react";

function CustomerLoginForm({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleLogin = (e) => {
    e.preventDefault();
    const loginSuccess = onLogin(email, password);
    if (!loginSuccess) setError("Invalid credentials. Please try again.");
  };

  return (
    <div
      className="flex items-center justify-center h-screen bg-center bg-cover"
      style={{ backgroundImage: "url('/src/assets/signIn.jpg')" }}
    >
      <div className="flex items-center justify-start w-full h-screen bg-center bg-cover pl-60 ">
        <div className="w-full max-w-md p-8 px-4 bg-white rounded-lg shadow-lg md:px-8 lg:px-16">
          <h2 className="mb-6 text-2xl font-semibold text-center">
            Customer Login
          </h2>
          {error && <p className="mb-4 text-sm text-red-500">{error}</p>}
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-gray-700"
              >
                Email
              </label>
              <input
                type="email"
                id="email"
                className="w-full px-3 py-2 mt-1 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-700"
              >
                Password
              </label>
              <input
                type="password"
                id="password"
                className="w-full px-3 py-2 mt-1 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {/* Footer Links  */}
            <p className="justify-end mt-4 text-center text-gray-600">
              New to CropCirle?{" "}
              <a href="/customer/SignUp" className="text-green-600 ">
                Sign Up
              </a>
            </p>
            <button
              type="submit"
              className="w-full px-4 py-2 font-semibold text-white transition duration-150 ease-in-out bg-green-600 rounded-md hover:bg-green-700"
            >
              Login
            </button>
            <a
              href="/customer/forgot-password"
              className="text-center text-gray-600 "
            >
              forgot password?
            </a>
          </form>
        </div>
      </div>
    </div>
  );
}

export default CustomerLoginForm;
