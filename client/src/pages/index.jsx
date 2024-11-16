// HomePage.js


import React from 'react';
import { NavLink } from 'react-router-dom';
import Navbar from '../components/Shared/Navbar';
import Footer from '../components/Shared/Footer';
import HeroSection from '../components/HomePage/HeroSection'
import FarmersSection from '../components/HomePage/FarmersSection'
import BuyersSection from '../components/HomePage/BuyersSection'

const navLinks = [
  { path: "/", label: "Home" },
  { path: "/about", label: "About" },
  { path: "/service", label: "Service" },
  { path: "/contact", label: "Contact Us" },
];



const HomePage = () => {
  return (


    <div>
      <Navbar navLinks={navLinks} bgcolor="#000" />

      <>
        <HeroSection />
        <FarmersSection />
        <BuyersSection />


      </>
      <Footer links={navLinks} bgcolor="#2d3748"></Footer>
    </div>
  );
};



export default HomePage



