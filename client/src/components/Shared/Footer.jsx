import React from "react";
import PropTypes from "prop-types";
import { Link } from "react-router-dom";

const Footer = ({ links, bgcolor }) => {
  const currentYear = new Date().getFullYear();

  return (
    <footer
      className={`w-full px-6 py-8 bg-gray-800 text-white backdrop-blur-md`}
      style={{ backgroundColor: bgcolor }}
    >
      {/* Top Section */}
      <div className="flex flex-col items-center justify-between gap-6 mb-8 md:flex-row">
        {/* Contact Info */}
        <div className="text-center md:text-left">
          <h4 className="mb-2 text-xl font-semibold">Contact Us</h4>
          <p>
            Email:{" "}
            <a
              href="mailto:info@cropcircle.com"
              className="text-green-400 hover:underline"
            >
              info@cropcircle.com
            </a>
          </p>
          <p>
            Phone:{" "}
            <a
              href="tel:+1234567890"
              className="text-green-400 hover:underline"
            >
              +1 (234) 567-890
            </a>
          </p>
        </div>

        {/* Quick Links */}
        <div className="text-center md:text-left">
          <h4 className="mb-2 text-xl font-semibold">Quick Links</h4>
          <ul className="flex flex-col gap-4 md:flex-row">
            <li>
              <Link
                to="/privacy-policy"
                className="text-green-400 hover:underline"
              >
                Privacy Policy
              </Link>
            </li>
            <li>
              <Link
                to="/terms-and-conditions"
                className="text-green-400 hover:underline"
              >
                Terms and Conditions
              </Link>
            </li>
            <li>
              <Link to="/help" className="text-green-400 hover:underline">
                Help
              </Link>
            </li>
            <li>
              <Link to="/faq" className="text-green-400 hover:underline">
                FAQ
              </Link>
            </li>
          </ul>
        </div>

        {/* Dynamic Links */}
        <div className="text-center md:text-left">
          <h4 className="mb-2 text-xl font-semibold">Explore</h4>
          <ul className="flex flex-col gap-4 md:flex-row">
            {links.map((link, index) => (
              <li key={index}>
                <Link
                  to={link.path}
                  className="text-green-400 hover:underline"
                >
                  {link.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Bottom Section */}
      <div className="pt-4 text-center border-t border-gray-700">
        <p className="text-sm">
          &copy; {currentYear} CropCircle. All rights reserved.
        </p>
      </div>
    </footer>
  );
};

Footer.propTypes = {
  links: PropTypes.arrayOf(
    PropTypes.shape({
      path: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
    })
  ).isRequired,
  bgcolor: PropTypes.string,
};

export default Footer;
