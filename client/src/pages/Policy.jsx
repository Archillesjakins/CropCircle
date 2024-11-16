import React from "react";
import { Link } from "react-router-dom";
import PropTypes from "prop-types";
import Navbar from "../components/Shared/Navbar";
import Footer from "../components/Shared/Footer";




const PolicyAgreement = () => {
    const navLinks = [
        { path: "/", label: "Home" },
        { path: "/about", label: "About" },
        { path: "/service", label: "Service" },
        { path: "/contact", label: "Contact Us" },
      ];
  return (
    <div>
      {/* Navbar */}
      <Navbar navLinks={navLinks} />

      {/* Main Content Section */}
      <main className="px-4 pt-20 bg-white md:px-8">
        <section className="max-w-4xl py-8 mx-auto">
          <h1 className="mb-6 text-3xl font-bold text-green-600">Privacy Policy</h1>

          <div className="space-y-4 text-lg leading-relaxed text-gray-800">
            <p>
              Welcome to CropCircle. This Privacy Policy explains how we collect,
              use, and protect your personal information. By using our services,
              you agree to the practices described in this policy.
            </p>
            <h2 className="mt-4 mb-2 text-2xl font-semibold text-green-600">
              1. Information We Collect
            </h2>
            <p>
              We collect personal information when you sign up for our services,
              place orders, or engage with us on our platform. The types of data
              we collect include your name, email address, phone number, and payment
              information.
            </p>
            <h2 className="mt-4 mb-2 text-2xl font-semibold text-green-600">
              2. How We Use Your Information
            </h2>
            <p>
              The information we collect is used to provide our services, process
              payments, communicate with you, and improve the user experience on
              our platform.
            </p>
            <h2 className="mt-4 mb-2 text-2xl font-semibold text-green-600">
              3. Data Security
            </h2>
            <p>
              We implement appropriate security measures to protect your personal
              information from unauthorized access, disclosure, or alteration.
            </p>
            <h2 className="mt-4 mb-2 text-2xl font-semibold text-green-600">
              4. Sharing Your Information
            </h2>
            <p>
              We do not sell or rent your personal information to third parties.
              We may share your information with trusted partners only when necessary
              to provide our services or comply with legal obligations.
            </p>
            <h2 className="mt-4 mb-2 text-2xl font-semibold text-green-600">
              5. Your Rights
            </h2>
            <p>
              You have the right to access, correct, and delete your personal
              information. If you wish to exercise any of these rights, please contact
              us at the information below.
            </p>
            <h2 className="mt-4 mb-2 text-2xl font-semibold text-green-600">
              6. Changes to This Policy
            </h2>
            <p>
              We may update this Privacy Policy from time to time. We will notify you
              of any changes by posting the updated policy on our platform.
            </p>
            <div className="mt-8 text-center">
              <Link
                to="/"
                className="px-6 py-3 text-lg font-semibold text-white transition duration-300 bg-green-600 rounded-lg shadow-md hover:bg-green-700 focus:outline-none focus:ring-4 focus:ring-green-500 focus:ring-opacity-50"
              >
                Accept Policy
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <Footer links={navLinks}  />
    </div>
  );
};

PolicyAgreement.propTypes = {
  navLinks: PropTypes.arrayOf(
    PropTypes.shape({
      path: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
    })
  ).isRequired,
  bgcolor: PropTypes.string,
};

export default PolicyAgreement;
