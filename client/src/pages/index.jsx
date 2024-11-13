// HomePage.js

import React from 'react';
import { NavLink } from 'react-router-dom';

const Home = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen px-4 bg-gray-100">
      {/* Hero Section */}
      <div className="py-12 text-center">
        <h1 className="mb-4 text-4xl font-bold text-gray-800">Welcome to CropCircle</h1>
        <p className="mb-8 text-lg text-gray-600">
          Connecting farmers with customers for seamless trading.
        </p>
        <button className="px-6 py-2 text-white transition duration-300 ease-in-out bg-green-500 rounded-full hover:bg-green-600">
          Get Started
        </button>
      </div>

      {/* User Selection Area */}
      <div className="flex flex-col items-center gap-8 mt-12 md:flex-row">
        {/* Customer Card */}
        <div className="w-full p-6 text-center bg-white rounded-lg shadow-lg md:w-80">
          <h2 className="mb-4 text-2xl font-semibold text-blue-500">For Customers</h2>
          <p className="mb-6 text-gray-600">
            Shop products directly from local farmers. Track orders, manage your cart, and more.
          </p>
          <div className="flex justify-center gap-4">
            <NavLink to="/customer/login">
              <button className="px-4 py-2 text-white transition duration-300 bg-blue-500 rounded-lg hover:bg-blue-600">
                Sign In
              </button>
            </NavLink>
            <NavLink to="/customer/signup">
              <button className="px-4 py-2 text-blue-500 transition duration-300 bg-gray-200 rounded-lg hover:bg-gray-300">
                Sign Up
              </button>
            </NavLink>
          </div>
        </div>

        {/* Farmer Card */}
        <div className="w-full p-6 text-center bg-white rounded-lg shadow-lg md:w-80">
          <h2 className="mb-4 text-2xl font-semibold text-green-500">For Farmers</h2>
          <p className="mb-6 text-gray-600">
            Sell your products, manage inventory, and connect with customers easily.
          </p>
          <div className="flex justify-center gap-4">
            <NavLink to="/farmer/login">
              <button className="px-4 py-2 text-white transition duration-300 bg-green-500 rounded-lg hover:bg-green-600">
                Sign In
              </button>
            </NavLink>
            <NavLink to="/farmer/signup">
              <button className="px-4 py-2 text-green-500 transition duration-300 bg-gray-200 rounded-lg hover:bg-gray-300">
                Sign Up
              </button>
            </NavLink>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
