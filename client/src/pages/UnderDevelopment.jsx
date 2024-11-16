import React from "react";
import leaf from '../assets/images/leaf.png'

const UnderDevelopment = ({navURL}) => {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-50">
      <div className="w-full max-w-lg p-8 text-center bg-white rounded-lg shadow-lg">
        <h1 className="mb-6 text-4xl font-bold text-gray-800">Page Under Development</h1>
        <p className="mb-4 text-xl text-gray-600">
          We're currently working on something awesome! Please check back later.
        </p>
        <div className="flex items-center justify-center mt-6">
          <div className="animate-pulse">
            <img src={leaf} alt="leaf" className="w-24" />
          </div>
        </div>
        <p className="mt-4 text-gray-500 text-md">
          Thank you for your patience. We’re making this space better for you!
        </p>
        <div className="mt-6">
          <a
            href={navURL}
            className="px-6 py-3 text-white transition duration-300 bg-green-600 rounded-lg hover:bg-green-700"
          >
            Go Back to Homepage
          </a>
        </div>
      </div>
    </div>
  );
};

export default UnderDevelopment;
