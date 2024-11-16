import React from "react";
import { Link } from "react-router-dom";

const NotFound = () => {
  return (
    <div className="flex items-center justify-center min-h-screen p-4 bg-gray-50">
      <div className="w-full max-w-lg p-8 text-center bg-white rounded-lg shadow-lg">
        <h1 className="text-6xl font-extrabold text-gray-800">404</h1>
        <h2 className="mt-4 text-2xl font-semibold text-gray-700">
          Oops! Page Not Found.
        </h2>
        <p className="mt-2 text-lg text-gray-500">
          We can't seem to find the page you're looking for. It may have been
          moved or deleted.
        </p>
        <div className="mt-8">
          <Link
            to="/"
            className="px-6 py-3 text-lg font-semibold text-white transition duration-300 bg-green-600 rounded-lg shadow-md hover:bg-green-700 focus:outline-none focus:ring-4 focus:ring-green-500 focus:ring-opacity-50"
          >
            Go to Home
          </Link>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
